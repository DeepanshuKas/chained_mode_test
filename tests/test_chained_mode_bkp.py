import ipaddress
import json
import pytest
import os
import time

from .lib_helper import APIC
from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from acc_pyutils.exceptions import KctlExecutionFailed
from tests import lib, lib_helper
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             MACVLAN_ASSOCIATED_INTERFACE,
                             APIC_USERNAME,
                             APIC_PASSWORD)

LOG = logger.get_logger(__name__)

CONFIG_FILE = os.path.abspath('tests/input/cfg.py')
MACVLAN_CNI = "macvlan"
SRIOV_CNI = "sriov"
BRIDGE_CNI = "bridge"
IPVLAN_CNI = "ipvlan"
OVS_CNI = "ovs"

# different modes of configuring traffic visibility with macvlan
MACVLAN_BRIDGE_MODE = "bridge"
MACVLAN_PRIVATE_MODE = "private"
MACVLAN_VEPA_MODE = "vepa"
L2_MODE = 'l2'
L3_MODE = 'l3'
IPVLAN_TAGGED_MODE = 'tagged'
IPVLAN_UNTAGGED_MODE = 'untagged'

POD_TEMPLATE = "wbitt.yaml"
NAD_TEMPLATE = "network_attachment_definition.yaml"
NNCP_TEMPLATE = "node_network_configuration_policy.yaml"
NAD_VLAN_MAP_CR_TEMPLATE = "nad_vlan_map_cr.yaml"
NFC_CR_TEMPLATE = 'network_fabric_configuration.yaml'
FABRICVLANPOOL_TEMPLATE = "fabricvlanpool.yaml"

OPENSHIFT_SRIOV_NETWORK_OPERATOR_NAMESPACE_NAME = "openshift-sriov-network-operator"
DEVICE_PLUGIN_CONFIGMAP_NAME = "device-plugin-config"

MACVLAN_NAD_NAME = 'macvlan-nad'
SRIOV_NAD_NAME = 'sriov-nad'
BRIDGE_NAD_NAME = 'bridge-nad'
OVS_NAD_NAME = 'ovs-nad'
IPVLAN_NAD_NAME = 'ipvlan-nad'

CONFIGMAP_NAMESPACE = 'aci-containers-system'
HOST_AGENT_IMAGE_PREFIX = 'quay.io/noiro/aci-containers-host'
HOST_AGENT_OVS_CNI_IMAGE_PREFIX = 'quay.io/noiro/aci-containers-host-ovscni'


def compare_apic_subnets_to_input_subnets(apic_subnets,input_subnets):
    if len(apic_subnets) != len(input_subnets):
        return False
    scope_mapping = {
        'public': 'advertise-externally',
        'shared': 'shared-between-vrfs',
    }
    control_mapping = {
        'querier': 'querier-ip',
        'no-default-gateway': 'no-default-svi-gateway',
        'nd': 'nd-ra-prefix'
    }
    def translate_subnets_field_name(item, mapping):
        return [mapping.get(term, term) for term in item if term]
    def filter_scope_and_control_from_apic_subnets(subnet):
        if 'fvSubnet' in subnet:
            attrs = subnet['fvSubnet']['attributes']
            return {
                'subnet': attrs['ip'],
                'scope': translate_subnets_field_name(attrs.get('scope', '').split(','), scope_mapping),  # Convert and translate scopes
                'control': translate_subnets_field_name(attrs.get('ctrl', '').split(','), control_mapping)  # Convert and translate controls
            }
        else:
            return {
                'subnet': subnet['subnet'],
                'scope': subnet['scope'],
                'control': subnet['control'],
            }
    filtered_apic_subnets = [filter_scope_and_control_from_apic_subnets(s) for s in apic_subnets]

    filtered_apic_subnets_sorted = sorted(filtered_apic_subnets, key=lambda ns: ns['subnet'])
    input_subnets_sorted = sorted(input_subnets, key=lambda ns: ns['subnet'])

    def compare_scope(sub1,sub2):
        scope1 = sub1.get('scope', [])
        scope2 = sub2.get('scope', [])
        if "private" in scope1 and "advertise-externally" in scope2:
            return False
        if "private" in scope1 and len(scope1) == 1 and not scope2:
            return True
        if (scope1 and not scope2) or (scope2 and not scope1):
            return False

        if scope1 and scope2:
            scope1_filtered = [term for term in scope1 if term != "private"]
            if len(scope1_filtered) != len(scope2):
                return False
            if sorted(scope1_filtered) != sorted(scope2):
                return False
        return True

    def compare_control(sub1,sub2):
        control1 = sub1.get('control', [])
        control2 = sub2.get('control', [])
        if (control1 and not control2) or (control2 and not control1):
            return False
        if control1 and control2:
            if sorted(control1) != sorted(control2):
                return False
        return True

    # Compare the apic subnets to input subnet
    for sub1, sub2 in zip(filtered_apic_subnets_sorted, input_subnets_sorted):
        if sub1['subnet'] != sub2['subnet']:
            return False
        control = compare_control(sub1,sub2)
        scope = compare_scope(sub1,sub2)
        if not control or not scope:
            return False
    return control and scope


def check_chained_mode():
    """Check CNI in chained mode

    1. Get acc-provision input file.
    2. If 'secondary_interface_chaining' or 'primary_interface_chaining' is 'true' under section
       'chained_cni_config' then, it's chained CNI mode.
    """
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    if apic_provision.get("chained_cni_config") and (
        apic_provision["chained_cni_config"].get("secondary_interface_chaining") or apic_provision[
            "chained_cni_config"].get("primary_interface_chaining")):
        return True
    return False


pytestmark = pytest.mark.skipif(check_chained_mode() is False, reason="Setup : "
                                "Not applicable for non chained mode setup")


def check_global_vlan_mode():
    """Check if setup in global VLAN mode

    1. Get acc-provision input file.
    2. If 'use_global_scope_vlan' is 'true' under section 'chained_cni_config' then, it's
       global vlan mode.
    """
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    if apic_provision.get("chained_cni_config") and apic_provision[
            "chained_cni_config"]["use_global_scope_vlan"]:
        return True
    return False


def check_auto_insertion_enabled():
    """Check CNI auto-insertion in NAD is enabled

    1. Get acc-provision input file.
    2. If 'auto_insertion_for_nad' is 'true' under section 'chained_cni_config' then, it's
       in CNI auto-insertion mode.
    """
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    if apic_provision.get("chained_cni_config") and apic_provision[
            "chained_cni_config"].get("auto_insertion_for_nad"):
        return True
    return False


def prepare_image_name(image_type):
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    if image_type == 'ovs_cni':
        if apic_provision['registry'].get('use_digest'):
            return HOST_AGENT_OVS_CNI_IMAGE_PREFIX + '@sha256:' + (
                apic_provision['registry'][
                    'aci_containers_host_ovscni_version'])
        else:
            return HOST_AGENT_OVS_CNI_IMAGE_PREFIX + ':' + (
                apic_provision['registry'][
                    'aci_containers_host_ovscni_version'])
    else:
        if apic_provision['registry'].get('use_digest'):
            return HOST_AGENT_IMAGE_PREFIX + '@sha256:' + (
                apic_provision['registry']['aci_containers_host_version'])
        else:
            return HOST_AGENT_IMAGE_PREFIX + ':' + (
                apic_provision['registry']['aci_containers_host_version'])


def create_pods(nad_name, cni_type, base_fixture, namespace='default'):
    kapi, pods = KubeAPI(), {}
    for _pod in ['multitool-1', 'multitool-2']:
        pod_input = {'name': _pod,
                     'labels': {'cni': cni_type},
                     'namespace': namespace,
                     'annotations': nad_name,
                     'template': POD_TEMPLATE}
        lib.create_resource_from_template(pod_input, base_fixture)
        pods[_pod] = kapi.get_detail('pod', namespace=namespace, **{'name': _pod})
    return pods


def delete_pods(namespace='default'):
    kapi = KubeAPI()
    for _pod in ['multitool-1', 'multitool-2']:
        LOG.info("Deleting pod[%s]" % _pod)
        kapi.delete_object('pod', _pod,
                           namespace=namespace)


def configure_pod_vlan_iface(pod_name, vlan, pod_ip, base_fixture,
                             source_subnet=None, dest_subnet=None):
    """Configuring additional interface in pod

    1. Add new interface with VLAN type.
    2. Bring up newly added interface.
    3. Assign IP address to interface.
    """
    kapi = KubeAPI()
    try:
        cmd_add_iface = "ip link add link net1 name net1." + str(
            vlan) + " type vlan id " + str(vlan)
        kapi.kexec(pod_name, cmd_add_iface)
        cmd_iface_up = "ip link set dev net1." + str(vlan) + " up"
        kapi.kexec(pod_name, cmd_iface_up)
        cmd_iface_addr = "ip addr add " + pod_ip + " dev net1." + str(vlan)
        kapi.kexec(pod_name, cmd_iface_addr)

        if source_subnet and dest_subnet:
            source_subnet_gateway = str(ipaddress.IPv4Network(source_subnet)[1])
            cmd_route_add = "ip route add " + dest_subnet + " via " + (
                source_subnet_gateway)
            kapi.kexec(pod_name, cmd_route_add)
    except KctlExecutionFailed as ex:
        LOG.error("Failed to configure interface. %s", (ex.message))
        raise


def normalize_vlans(secondary_vlans):
    """Converts given secondary vlans in list to plain list

    1. Get vlan list. eg. [1,2,3-7,[8,9]]
    2. Convert to plain list. eg. [1,2,3,4,5,6,7,8,9]
    """
    normalized_vlans = []
    if not secondary_vlans:
        return normalized_vlans
    for vlan in secondary_vlans:
        if isinstance(vlan, list):
            normalized_vlans.extend(vlan)
        elif ',' in str(vlan):
            values = [int(val) for val in vlan.split(',')]
            normalized_vlans.extend(values)
        elif '-' in str(vlan):
            start, end = map(int, vlan.split('-'))
            result_vlans = list(range(start, end + 1))
            normalized_vlans.extend(result_vlans)
        else:
            normalized_vlans.append(int(vlan))
    return normalized_vlans


def prepare_nncp_and_interface_name(interface_type, nad_name, vlans):
    if interface_type == 'vlan':
        nncp_name = MACVLAN_ASSOCIATED_INTERFACE + '-vlan-' + str(vlans[1])
        interface_name = MACVLAN_ASSOCIATED_INTERFACE + '.' + str(vlans[1])
        return nncp_name, interface_name
    elif interface_type == 'linux-bridge' or interface_type == 'ovs-bridge':
        return nad_name, nad_name


def delete_nncp(nncp_name):
    lib.wait_for_nncp_successfully_configured(nncp_name)
    kapi = KubeAPI()
    kapi.delete_object('nncp', nncp_name)


def setup_nncp(nncp_name, nncp_state, nad_name, interface_name,
               interface_type, vlans=[]):
    kapi = KubeAPI()
    nncp_input = {
        'name': nncp_name,
        'interface_name': interface_name,
        'type': interface_type,
        'nad_name': nad_name,
        'base_interface': MACVLAN_ASSOCIATED_INTERFACE,
        'interface_type': interface_type,
        'state': nncp_state,
        'template': NNCP_TEMPLATE
    }
    if interface_type == 'vlan':
        nncp_input['vlan'] = vlans[1]
    lib.apply_resource_from_template(nncp_input)


def get_nodes():
    """Get kubernetes nodes

    1. Get the kubernetes node details.
    2. Prepare list of node names.
    """
    kapi = KubeAPI()
    nodes = kapi.get_detail('nodes')
    node_list = list()
    for node in nodes['items']:
        node_list.append(node['metadata']['name'])
    return node_list


def check_namespace(ns_name):
    try:
        kapi = KubeAPI()
        ns = kapi.get('namespace', name=ns_name)
        return True if ns else False
    except KctlExecutionFailed as ex:
        return False


def check_configmap(ns_name, cm_name):
    try:
        kapi = KubeAPI()
        cm = kapi.get_detail('cm', name=cm_name, namespace=ns_name)
        return True if cm else False
    except KctlExecutionFailed as ex:
        return False


def get_sriov_pf():
    """Get the PF name used for SR-IOV

    1. Get all the node names in list.
    2. Get the config details of device-plugin-config configMap.
    3. Check if is there resource list for any of the nodes.
    4. Get the resource name (ie. PF name) from the resource list.
    """
    resource_name = None
    kapi = KubeAPI()

    if not check_namespace(OPENSHIFT_SRIOV_NETWORK_OPERATOR_NAMESPACE_NAME) or (

        not check_configmap(OPENSHIFT_SRIOV_NETWORK_OPERATOR_NAMESPACE_NAME,
                            DEVICE_PLUGIN_CONFIGMAP_NAME)
    ):
        return resource_name

    config_map_details = kapi.get_detail('cm', namespace='openshift-sriov-network-operator',
                                         name='device-plugin-config')
    nodes = get_nodes()
    for node in nodes:
        node_resource_details = config_map_details['data'].get(node)
        if node_resource_details:
            resource_details = json.loads(node_resource_details)
            if resource_details['resourceList']:
                resource_name = resource_details['resourceList'][0]['resourceName']
                return resource_name
    return resource_name


def get_sriov_vf_id_from_pci_address(node_name, pci_address):
    kapi = KubeAPI()
    kwargs = {"name": node_name}
    node_states = kapi.get_detail("sriovnetworknodestate",
                                  namespace='openshift-sriov-network-operator', **kwargs)
    for interface in node_states.get('status', {}).get('interfaces', []):
        if 'Vfs' in interface.keys():
            for vf in interface.get('Vfs', []):
                if vf.get('pciAddress') == pci_address:
                    return vf.get('vfID')
            break


def get_pci_address_from_pod(pod_name, sriov_intf):
    try:
        kapi = KubeAPI()
        env_var_name = "PCIDEVICE_OPENSHIFT_IO_" + sriov_intf.upper()
        cmd_get_pci_address = "printenv | grep " + env_var_name + "="
        env_var = kapi.kexec(pod_name, cmd_get_pci_address, interpreter='sh -c')
        if env_var:
            pci_address = env_var.decode().split('\n')[0].split('=')[1]
            return pci_address
    except KctlExecutionFailed as ex:
        LOG.error("Failed to get PCI address of VF. %s " % (ex.message))
        raise


def get_host_agent_of_pod(pod_name):
    kapi = KubeAPI()
    _, _, node_name = lib.get_pod_details(pod_name)
    pods = kapi.get_detail('pods', namespace='aci-containers-system',
                    labels='name=aci-containers-host')
    for pod in pods['items']:
        if pod.get('spec', {}).get('nodeName', '') == node_name:
            return pod['metadata']['name']


def remove_vlan_from_vf(pod_name, sriov_intf, vf_id):
    try:
        host_agent_pod = get_host_agent_of_pod(pod_name)
        kapi = KubeAPI()
        cmd_reset_vlan = "ip link set dev " + str(sriov_intf) + " vf " + str(vf_id) + " vlan 0"
        kapi.kexec(host_agent_pod, cmd_reset_vlan, namespace='aci-containers-system')
    except KctlExecutionFailed as ex:
        LOG.error("Failed to remove vlan from VF interface. %s" % (ex.message))
        raise


def unset_vf_vlan(pod_list):
    sriov_intf = get_sriov_pf()
    for pod in pod_list:
        _, _, node_name = lib.get_pod_details(pod)
        pci_address = get_pci_address_from_pod(pod, sriov_intf)
        if pci_address:
            vf_id = get_sriov_vf_id_from_pci_address(node_name, pci_address)
            if vf_id:
                remove_vlan_from_vf(pod, sriov_intf, vf_id)


def check_pods_on_same_node(pod_details):
    node_name = ''
    for pod_name in pod_details.keys():
        if node_name == pod_details[pod_name]['spec']['nodeName']:
            return True
        node_name = pod_details[pod_name]['spec']['nodeName']
    return False


def collect_all_pods_ip(pod_details, nad_name):
    pod_ips = []
    for pod_name in pod_details.keys():
        network_status = json.loads(pod_details[pod_name]['metadata'][
            'annotations']['k8s.v1.cni.cncf.io/network-status'])
        for status in network_status:
            if status['name'] == pod_details[pod_name]['metadata'][
                'namespace'] + '/' + nad_name:
                pod_ips.append(status['ips'][0])
    return pod_ips


def add_vlan_type_interfaces_and_verify_traffic(pod_details, vlan_1, vlan_2,
                                                base_fixture,
                                                namespace='default',
                                                nad_name=None,
                                                use_default_ips=True,
                                                configure_interfaces=True,
                                                sriov_cni_used=False):
    """Verifies traffic between VLAN interfaces

    1. Add 1 interface of type VLAN in each pod.
    2. Check traffic between VLAN interfaces of 2 pods:
       i. If interfaces created with same VLANs then, traffic should work.
       ii. If interfaces created with different VLANs then, traffic should not work.
    """
    p1_name, p2_name = (pod_details['multitool-1']['metadata']['name'],
                        pod_details['multitool-2']['metadata']['name'])
    pod_details[p1_name], pod_details[p2_name] = (pod_details.pop('multitool-1'),
                                    pod_details.pop('multitool-2'))
    pod_ip = {}
    if use_default_ips :
        pod_ip[p1_name] = "192.168.103.2/24"
        pod_ip[p2_name] = "192.168.103.4/24"
    else:
        pod_ips = collect_all_pods_ip(pod_details, nad_name)
        pod_ip[p1_name] = pod_ips[0]
        pod_ip[p2_name] = pod_ips[1]

    if configure_interfaces:
        configure_pod_vlan_iface(p1_name, vlan_1, pod_ip[p1_name], base_fixture)
        configure_pod_vlan_iface(p2_name, vlan_2, pod_ip[p2_name], base_fixture)

    LOG.info("Testing ping traffic between pods %s %s" % (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        src_pod_cni_type = pod_details[p_name].get('metadata', {}).get('labels', {}).get('cni')
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        if sriov_cni_used and src_pod_cni_type == 'sriov':
            # Need to unset vlan on VF
            unset_vf_vlan([p_name])
        dest_pod_cni_type = pod_details[dst_pod].get('metadata', {}).get('labels', {}).get('cni')
        if sriov_cni_used and dest_pod_cni_type == 'sriov':
            unset_vf_vlan([dst_pod])
        tips = pod_ip[dst_pod].split("/")[0]
        LOG.info("Target pod ips are : %s" % tips)
        if vlan_1 == vlan_2:
            # For same encap, traffic should pass
            lib_helper.check_ping_from_pod(
                p_name, pod_details[p_name]['metadata']['namespace'], tips,
                target='pod')
        else:
            # For different encap, traffic should fail
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    p_name, pod_details[p_name]['metadata']['namespace'], tips,
                    target='pod')


def get_vlans_from_nfnas(kapi):
    nfnas = kapi.get_detail('nodefabricnetworkattachment',
                            namespace=CONFIGMAP_NAMESPACE)
    assert nfnas['items'], ("no nodefabricnetworkattachment present after "
                            "nad creation")
    nfna_vlan_list = []
    for nfna in nfnas['items']:
        nfna_vlan_list_string = nfna.get('spec', {}).get('encapVlan', {}).get('vlanList', '')
        if '[' in nfna_vlan_list_string:
            raw_nfna_vlan_list = nfna_vlan_list_string[1:-1].split(',')
        else:
            raw_nfna_vlan_list = nfna_vlan_list_string.split(',')
        nfna_vlan_list = normalize_vlans(raw_nfna_vlan_list)
        break
    return nfna_vlan_list


def compare_nad_vlans_with_fabricvlanpool_vlans(nad_and_ns_name,
                                                fabricvlanpool_vlans):
    kapi = KubeAPI()

    fabricvlanpool_vlan_list = normalize_vlans(fabricvlanpool_vlans)

    # compare fabricvlanpool vlans with all the nfna vlans of the nad
    nfnas = kapi.get_detail('nodefabricnetworkattachment',
                            namespace=CONFIGMAP_NAMESPACE)
    assert nfnas['items'], ("no nodefabricnetworkattachment present after "
                            "nad creation")

    nfnas_wrt_nad = 0
    for nfna in nfnas['items']:
        if nad_and_ns_name in nfna.get('metadata', {}).get('name', ''):
            nfna_vlan_list_string = nfna.get('spec', {}).get('encapVlan', {}).get('vlanList', '')
            if '[' in nfna_vlan_list_string:
                raw_nfna_vlan_list = nfna_vlan_list_string[1:-1].split(',')
            else:
                raw_nfna_vlan_list = nfna_vlan_list_string.split(',')
            nfna_vlan_list = normalize_vlans(raw_nfna_vlan_list)

            assert fabricvlanpool_vlan_list == nfna_vlan_list
            nfnas_wrt_nad += 1

    assert nfnas_wrt_nad != 0, ("no nodefabricnetworkattachment present with respect to "
                                "the nad created")


def get_vlans_from_fabricvlanpool(kapi, ns_name='default'):
    vlan_list_string = []

    fabric_vlan_pool = kapi.get_detail('fabricvlanpool',
                            namespace=ns_name)

    if not fabric_vlan_pool or not fabric_vlan_pool.get('items'):
        fabric_vlan_pool = kapi.get_detail('fabricvlanpool',
                            namespace=CONFIGMAP_NAMESPACE)

    assert fabric_vlan_pool['items'], ("no fabricvlanpool available")

    for vlan_pool in fabric_vlan_pool['items']:
        vlan_list_string = normalize_vlans(
            vlan_pool.get('spec', {}).get('vlans', []))
        if len(vlan_list_string) > 3:
            break
        else:
            vlan_list_string = []
    return vlan_list_string


def compare_nfna_vlans_with_nad_vlans(kapi, nad_vlans):
    nfnas = kapi.get_detail('nodefabricnetworkattachment',
                            namespace=CONFIGMAP_NAMESPACE)
    assert nfnas['items'], ("no nodefabricnetworkattachment present after "
                            "nad creation")
    for nfna in nfnas['items']:
        nad_vlan_list = normalize_vlans(nad_vlans.split(', '))
        nfna_vlan_list_string = nfna.get('spec', {}).get('encapVlan', {}).get('vlanList', '')
        if '[' in nfna_vlan_list_string:
            raw_nfna_vlan_list =  nfna_vlan_list_string[1:-1].split(',')
        else:
            raw_nfna_vlan_list =  nfna_vlan_list_string.split(',')
        nfna_vlan_list = normalize_vlans(raw_nfna_vlan_list)
        assert nad_vlan_list == nfna_vlan_list


def compare_nfnas(kapi, nfnas_before_restart):
    nfnas = kapi.get_detail('nodefabricnetworkattachment',
                            namespace=CONFIGMAP_NAMESPACE)
    assert nfnas['items'], ("no nodefabricnetworkattachment present after "
                            "nad creation")

    nfna_names_before_restart = []
    for nfna_before in nfnas_before_restart['items']:
        nfna_names_before_restart.append(nfna_before['metadata']['name'])

    nfna_names_after_restart = []
    for nfna in nfnas['items']:
        nfna_names_after_restart.append(nfna['metadata']['name'])

    assert nfna_names_before_restart.sort() == nfna_names_after_restart.sort()


def remove_cni_from_nad_config(nad_config_manifest):
    for plugin in nad_config_manifest.get('plugins'):
        if plugin.get('type') in ['netop-cni', 'opflex-agent-cni']:
            nad_config_manifest['plugins'].remove(plugin)
            break
    return nad_config_manifest


@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_macvlan_bridge_same_encap(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE, MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture)


@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_macvlan_bridge_different_encap(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[1], base_fixture)


@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_macvlan_private_same_encap(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

    p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                        pods['multitool-2']['metadata']['name'])
    pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                    pods.pop('multitool-2'))
    pod_ip = {}
    pod_ip[p1_name] = "192.168.103.2/24"
    pod_ip[p2_name] = "192.168.103.4/24"

    configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name], base_fixture)
    configure_pod_vlan_iface(p2_name, vlans[0], pod_ip[p2_name], base_fixture)

    LOG.info("Testing ping traffic between pods %s %s" % (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tips = pod_ip[dst_pod].split("/")[0]
        LOG.info("Target pod ips are : %s" % tips)
        if check_pods_on_same_node(pods):
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    p_name, pods[p_name]['metadata']['namespace'], tips,
                    target='pod')
        else:
            lib_helper.check_ping_from_pod(
                p_name, pods[p_name]['metadata']['namespace'], tips,
                target='pod')


@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_macvlan_private_different_encap(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE, MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

    p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                        pods['multitool-2']['metadata']['name'])
    pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                    pods.pop('multitool-2'))
    pod_ip = {}
    pod_ip[p1_name] = "192.168.103.2/24"
    pod_ip[p2_name] = "192.168.103.4/24"

    configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name], base_fixture)
    configure_pod_vlan_iface(p2_name, vlans[1], pod_ip[p2_name], base_fixture)

    LOG.info("Testing ping traffic between pods %s %s" % (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tips = pod_ip[dst_pod].split("/")[0]
        LOG.info("Target pod ips are : %s" % tips)
        with pytest.raises(KctlExecutionFailed):
            lib_helper.check_ping_from_pod(
                p_name, pods[p_name]['metadata']['namespace'], tips,
                target='pod')


@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_macvlan_vepa_same_encap(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_VEPA_MODE, MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture)


'''@pytest.mark.skipif(get_sriov_pf() is None, reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_sriov_same_encap(base_fixture):
    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME)
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture, sriov_cni_used=True)
'''

'''@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_without_nad_encap_sriov_different_encap(base_fixture):
    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME)
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[1], base_fixture,
                                                sriov_cni_used=True)
'''

@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_macvlan_bridge_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name('vlan',
                                    MACVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', MACVLAN_NAD_NAME, interface_name,
               'vlan', vlans)

    try:
        nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
            'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
            interface_name)

        nad_input = {
            'name': MACVLAN_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
            vlans[1], base_fixture, nad_name=MACVLAN_NAD_NAME,
            use_default_ips=False, configure_interfaces=False)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', MACVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_macvlan_bridge_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name('vlan',
                                        MACVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', MACVLAN_NAD_NAME, interface_name, 'vlan',
               vlans)

    try:
        nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
            'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
            interface_name)
        nad_input = {
            'name': MACVLAN_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                    vlans[1], base_fixture)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', MACVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_macvlan_private_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name('vlan',
                                        MACVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', MACVLAN_NAD_NAME, interface_name, 'vlan', vlans)

    try:
        nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
            'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE,
            interface_name)
        nad_input = {
            'name': MACVLAN_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

        p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                            pods['multitool-2']['metadata']['name'])
        pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                        pods.pop('multitool-2'))
        pod_ip = {}
        pod_ips = collect_all_pods_ip(pods, MACVLAN_NAD_NAME)
        pod_ip[p1_name] = pod_ips[0]
        pod_ip[p2_name] = pod_ips[1]

        LOG.info("Testing ping traffic between pods %s %s" % (p1_name,
                                                              p2_name))
        for p_name in [p1_name, p2_name]:
            dst_pod = list({p1_name, p2_name} - {p_name})[0]
            tips = pod_ip[dst_pod].split("/")[0]
            LOG.info("Target pod ips are : %s" % tips)
            if check_pods_on_same_node(pods):
                with pytest.raises(KctlExecutionFailed):
                    lib_helper.check_ping_from_pod(
                        p_name, pods[p_name]['metadata']['namespace'], tips,
                        target='pod')
            else:
                lib_helper.check_ping_from_pod(
                    p_name, pods[p_name]['metadata']['namespace'], tips,
                    target='pod')
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', MACVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_macvlan_private_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name('vlan',
                                    MACVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', MACVLAN_NAD_NAME, interface_name, 'vlan', vlans)

    try:
        nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
            'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE,
            interface_name)
        nad_input = {
            'name': MACVLAN_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

        p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                            pods['multitool-2']['metadata']['name'])
        pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                        pods.pop('multitool-2'))
        pod_ip = {}
        pod_ip[p1_name] = "192.168.103.2/24"
        pod_ip[p2_name] = "192.168.103.4/24"
        configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name],
                                 base_fixture)
        configure_pod_vlan_iface(p2_name, vlans[1], pod_ip[p2_name],
                                 base_fixture)

        LOG.info("Testing ping traffic between pods %s %s" % (p1_name,
                                                              p2_name))
        for p_name in [p1_name, p2_name]:
            dst_pod = list({p1_name, p2_name} - {p_name})[0]
            tips = pod_ip[dst_pod].split("/")[0]
            LOG.info("Target pod ips are : %s" % tips)
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    p_name, pods[p_name]['metadata']['namespace'], tips,
                    target='pod')
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', MACVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_macvlan_vepa_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name('vlan',
                                    MACVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', MACVLAN_NAD_NAME, interface_name,
               'vlan', vlans)

    try:
        nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
            'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_VEPA_MODE,
            interface_name)
        nad_input = {
            'name': MACVLAN_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
            vlans[1], base_fixture, nad_name=MACVLAN_NAD_NAME,
            use_default_ips=False, configure_interfaces=False)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', MACVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)

'''
@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_sriov_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME, vlans[0])
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                sriov_cni_used=True)
'''

'''@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_with_nad_encap_sriov_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME, vlans[0])
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[1], base_fixture,
                                                sriov_cni_used=True)
'''

'''@pytest.mark.skipif(check_global_vlan_mode() is False,
                    reason="Global VLAN mode test")
@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_global_vlan_mode_with_same_encap_different_nads(base_fixture):
    resource_name = get_sriov_pf()
    sriov_nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME)
    sriov_nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(sriov_nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(sriov_nad_input, base_fixture)

    macvlan_nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    macvlan_nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(macvlan_nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(macvlan_nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    _pod1 = 'multitool-1'
    pod_input = {
        'name': _pod1,
        'labels': {'cni': 'sriov'},
        'annotations': sriov_nad_input['name'],
        'template': POD_TEMPLATE}
    lib.create_resource_from_template(pod_input, base_fixture)
    pods[_pod1] = kapi.get_detail('pod', **{'name': _pod1})

    _pod2 = 'multitool-2'
    pod_input = {
        'name': _pod2,
        'labels': {'cni': 'macvlan'},
        'annotations': macvlan_nad_input['name'],
        'template': POD_TEMPLATE}
    lib.create_resource_from_template(pod_input, base_fixture)

    pods[_pod2] = kapi.get_detail('pod', **{'name': _pod2})

    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                sriov_cni_used=True)
'''

'''@pytest.mark.skipif(check_global_vlan_mode() is False,
                    reason="Global VLAN mode test")
@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_global_vlan_mode_with_restart_host_and_controller(base_fixture):
    resource_name = get_sriov_pf()
    sriov_nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME)
    sriov_nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(sriov_nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(sriov_nad_input, base_fixture)

    macvlan_nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    macvlan_nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(macvlan_nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(macvlan_nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    _pod1 = 'multitool-1'
    pod_input = {
        'name': _pod1,
        'labels': {'cni': 'sriov'},
        'annotations': sriov_nad_input['name'],
        'template': POD_TEMPLATE}
    lib.create_resource_from_template(pod_input, base_fixture)
    pods[_pod1] = kapi.get_detail('pod', **{'name': _pod1})

    _pod2 = 'multitool-2'
    pod_input = {
        'name': _pod2,
        'labels': {'cni': 'macvlan'},
        'annotations': macvlan_nad_input['name'],
        'template': POD_TEMPLATE}
    lib.create_resource_from_template(pod_input, base_fixture)
    pods[_pod2] = kapi.get_detail('pod', **{'name': _pod2})

    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                sriov_cni_used=True)

    nfnas_before_restart = kapi.get_detail('nodefabricnetworkattachment',
                            namespace=CONFIGMAP_NAMESPACE)

    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)
    lib.restart_hostagent(namespace=CONFIGMAP_NAMESPACE)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                configure_interfaces=False,
                                                sriov_cni_used=True)
    compare_nfnas(kapi, nfnas_before_restart)
'''

@pytest.mark.usefixtures("clean_gen_templates")
def test_network_fabric_configuration_crud(base_fixture):
    nfc_input = {
        'name': 'networkfabricconfiguration',
        'vlans': '550',
        'aeps': 'test',
        'template': NFC_CR_TEMPLATE
    }
    lib.create_resource_from_template(nfc_input, base_fixture)

    kapi = KubeAPI()
    nfc = kapi.get_detail('networkfabricconfiguration')
    assert nfc['items'], ("Network Fabric Configuration resource not found")

    updated_vlans = '552'
    nfc_input['vlans'] = updated_vlans
    lib.apply_resource_from_template(nfc_input)

    nfc = kapi.get_detail('networkfabricconfiguration')
    assert nfc['items'], ("Network Fabric Configuration resource not found")
    assert updated_vlans == nfc['items'][0]['spec']['vlans'][0]['vlans']

    kapi.delete_object('networkfabricconfiguration', nfc_input['name'],
                       namespace=CONFIGMAP_NAMESPACE)

    nfc = kapi.get_detail('networkfabricconfiguration')
    assert len(nfc['items']) == 0, (
        "Network fabric configuration object exists after deleting")

    nadvlanmap = kapi.get_detail('nadvlanmap', namespace=CONFIGMAP_NAMESPACE)

    if nadvlanmap['items']:
        new_nadvlanmap_config = {
            'macvlan-test/' + MACVLAN_NAD_NAME : [
                {
                    'label': MACVLAN_NAD_NAME,
                    'vlans': '550-556, 558, 589'
                }
            ]
        }
        lib.add_nadvlanmapping(CONFIGMAP_NAMESPACE, new_nadvlanmap_config)
    else:
        new_nadvlanmap_config = {
            'name': 'nad-vlan-map',
            'nad_prefix': MACVLAN_NAD_NAME,
            'namespace': 'macvlan-test',
            'network_name': MACVLAN_NAD_NAME,
            'vlans': '550-556, 558, 589',
            'template': NAD_VLAN_MAP_CR_TEMPLATE
        }
        lib.apply_resource_from_template(new_nadvlanmap_config)

    try:
        nfc_input = {
            'name': 'networkfabricconfiguration',
            'nadvlanlabel': MACVLAN_NAD_NAME,
            'aeps': 'test',
            'template': NFC_CR_TEMPLATE
        }
        lib.create_resource_from_template(nfc_input, base_fixture)

        nfc = kapi.get_detail('networkfabricconfiguration')
        assert nfc['items'], ("Network Fabric Configuration resource not found")

        updated_vlans = '552'
        nfc_input['vlans'] = updated_vlans
        lib.apply_resource_from_template(nfc_input)

        nfc = kapi.get_detail('networkfabricconfiguration')
        assert nfc['items'], ("Network Fabric Configuration resource not found")
        assert updated_vlans == nfc['items'][0]['spec']['vlans'][0]['vlans']

        kapi.delete_object('networkfabricconfiguration', nfc_input['name'],
                        namespace=CONFIGMAP_NAMESPACE)

        nfc = kapi.get_detail('networkfabricconfiguration')
        assert len(nfc['items']) == 0, (
            "Network fabric configuration object exists after deleting")
    except Exception:
        raise
    finally:
        lib.remove_nadvlanmapping(CONFIGMAP_NAMESPACE,
                                  'macvlan-test/' + MACVLAN_NAD_NAME )


# With annotation of vlan list per NAD
@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_macvlan_bridge_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture)


@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_macvlan_bridge_different_encap(
    base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[1], base_fixture)


@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_macvlan_private_same_encap(
    base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

    p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                        pods['multitool-2']['metadata']['name'])
    pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                    pods.pop('multitool-2'))
    pod_ip = {}
    pod_ip[p1_name] = "192.168.103.2/24"
    pod_ip[p2_name] = "192.168.103.4/24"
    configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name],
                             base_fixture)
    configure_pod_vlan_iface(p2_name, vlans[0], pod_ip[p2_name],
                             base_fixture)

    LOG.info("Testing ping traffic between pods %s %s" % (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tips = pod_ip[dst_pod].split("/")[0]
        LOG.info("Target pod ips are : %s" % tips)
        if check_pods_on_same_node(pods):
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    p_name, pods[p_name]['metadata']['namespace'], tips,
                    target='pod')
        else:
            lib_helper.check_ping_from_pod(
                p_name, pods[p_name]['metadata']['namespace'], tips,
                target='pod')


@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_macvlan_private_different_encap(
    base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_PRIVATE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)

    p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                        pods['multitool-2']['metadata']['name'])
    pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                    pods.pop('multitool-2'))
    pod_ip = {}
    pod_ip[p1_name] = "192.168.103.2/24"
    pod_ip[p2_name] = "192.168.103.4/24"
    configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name],
                             base_fixture)
    configure_pod_vlan_iface(p2_name, vlans[1], pod_ip[p2_name],
                             base_fixture)

    LOG.info("Testing ping traffic between pods %s %s" % (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tips = pod_ip[dst_pod].split("/")[0]
        LOG.info("Target pod ips are : %s" % tips)
        with pytest.raises(KctlExecutionFailed):
            lib_helper.check_ping_from_pod(
                p_name, pods[p_name]['metadata']['namespace'], tips,
                target='pod')


@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_macvlan_vepa_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_VEPA_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture)


'''@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_sriov_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME, vlans[0])
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                sriov_cni_used=True)
'''

'''@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_annotation_vlan_list_per_nad_sriov_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME, vlans[0])
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'vlan_list': json.dumps(vlans),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[1], base_fixture,
                                                sriov_cni_used=True)
'''

@pytest.mark.skipif(check_global_vlan_mode() is True,
                    reason="Not Global VLAN mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_nad_vlan_map(base_fixture):
    kapi = KubeAPI()
    ns_input = {
        'name': 'nad-test',
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'nad-test',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    nad_vlan_map_cr_input = {
        'name': 'nad-vlan-map',
        'nad_prefix': MACVLAN_NAD_NAME,
        'namespace': 'nad-test',
        'network_name': 'macvlan-network',
        'vlans': '550-556, 558, 589',
        'template': NAD_VLAN_MAP_CR_TEMPLATE
    }
    lib.apply_resource_from_template(nad_vlan_map_cr_input)

    compare_nfna_vlans_with_nad_vlans(kapi, nad_vlan_map_cr_input['vlans'])

    nad_vlan_map_cr_input['vlans'] = '567, 570-577'
    lib.apply_resource_from_template(nad_vlan_map_cr_input)

    compare_nfna_vlans_with_nad_vlans(kapi, nad_vlan_map_cr_input['vlans'])

    kapi.delete_object('nadvlanmap', nad_vlan_map_cr_input['name'],
                       namespace=ns_input['name'])
    compare_nfna_vlans_with_nad_vlans(kapi, ''.join(
        apic_provision["chained_cni_config"]["secondary_vlans"]))


@pytest.mark.usefixtures("clean_gen_templates")
def test_nad_with_no_fabricvlanpool_in_namespace(base_fixture):
    ns_name = "nad-default-fabricvlanpool-test"
    ns_input = {
        'name': ns_name,
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    # create NAD
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': ns_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    nad_and_ns_name = ns_name + "-" + MACVLAN_NAD_NAME

    # get default fabricvlanpool VLANs
    try:
        kapi = KubeAPI()
        fabricvlanpool = kapi.get_detail('fabricvlanpool',
                                         name='default',
                                         namespace=CONFIGMAP_NAMESPACE)
    except KctlExecutionFailed as ex:
        LOG.error("Error while fetching default fabricvlanpool: %s", ex)
        raise

    fabricvlanpool_vlans = fabricvlanpool.get('spec', {}).get('vlans', [])

    compare_nad_vlans_with_fabricvlanpool_vlans(
        nad_and_ns_name, fabricvlanpool_vlans)


@pytest.mark.usefixtures("clean_gen_templates")
def test_nad_with_fabricvlanpool_in_namespace(base_fixture):
    ns_name = "nad-with-fabricvlanpool-test"
    ns_input = {
        'name': ns_name,
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    # create fabricvlanpool
    fabricvlanpool_vlans = ['750-799']
    fabricvlanpool_input = {
        'name': 'test-fabricvlanpool',
        'namespace': ns_name,
        'vlans': fabricvlanpool_vlans,
        'template': FABRICVLANPOOL_TEMPLATE
    }
    lib.create_resource_from_template(fabricvlanpool_input, base_fixture)

    # create NAD
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': ns_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    nad_and_ns_name = ns_name + "-" + MACVLAN_NAD_NAME

    compare_nad_vlans_with_fabricvlanpool_vlans(
        nad_and_ns_name, fabricvlanpool_vlans)


@pytest.mark.skipif(check_global_vlan_mode() is False,
                    reason="Global VLAN mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_fabricvlanpool_reflect_in_apic(base_fixture):
    kapi = KubeAPI()
    ns_name = "fabricvlanpool-reflect-apic-test"
    ns_input = {
        'name': ns_name,
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    # add fabricvlanpool
    vlan_from = '450'
    vlan_to = '499'
    vlan_range = vlan_from + "-" + vlan_to
    fabricvlanpool_vlans = [vlan_range]
    fabricvlanpool_input = {
        'name': 'test-fabricvlanpool-1',
        'namespace': ns_name,
        'vlans': fabricvlanpool_vlans,
        'template': FABRICVLANPOOL_TEMPLATE
    }
    lib.create_resource_from_template(fabricvlanpool_input, base_fixture)

    # check in apic if the added VLAN list reflected

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)

    config = {
        'apic_host': apic_provision['aci_config']['apic_hosts'][0],
        'apic_username': APIC_USERNAME,
        'apic_password': APIC_PASSWORD,
        'system_id': apic_provision['aci_config']['system_id'],
        'l3out': apic_provision['aci_config']['l3out']['name'],
        'ext_network': apic_provision[
            'aci_config']['l3out']['external_networks'][0],
        'vrf_name': apic_provision['aci_config']['vrf']['name'],
    }

    try:
        apic = ValidateApi(config)
    except Exception as ex:
        assert False, ("Apic login failed with error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))

    assert apic.is_vlan_pool_exists("secondary", "static",
                                    int(vlan_from), int(vlan_to)), (
        "secondary vlan pool not exist in apic")

    # delete fabricvlanpool
    kapi.delete_object('fabricvlanpool', fabricvlanpool_input['name'],
                       namespace=ns_name)

    # It is observed sometimes that after the deletion of the fabricvlanpool,
    # it still shows in APIC for few seconds.
    # Adding few seconds sleep to handle that.
    time.sleep(15)

    assert apic.is_vlan_pool_exists("secondary", "static",
                                    int(vlan_from), int(vlan_to)
                                    ) is False, (
        "vlan pool exists in apic after deletion")


@pytest.mark.skipif(check_auto_insertion_enabled() is False,
                    reason="CNI auto-insertion in NAD is not enabled")
@pytest.mark.usefixtures("clean_gen_templates")
def test_without_cni_in_macvlan_nad(base_fixture):
    nad_config_manifest = lib_helper.get_macvlan_nad_config_manifest(
        'macvlan.jsonnet', MACVLAN_NAD_NAME, MACVLAN_BRIDGE_MODE,
        MACVLAN_ASSOCIATED_INTERFACE)
    nad_config_manifest = remove_cni_from_nad_config(nad_config_manifest)
    nad_input = {
        'name': MACVLAN_NAD_NAME,
        'namespace': 'default',
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], MACVLAN_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture)


'''@pytest.mark.skipif(check_auto_insertion_enabled() is False,
                    reason="CNI auto-insertion in NAD is not enabled")
@pytest.mark.skipif(get_sriov_pf() is None,
                    reason="SR-IOV not enabled on workers")
@pytest.mark.usefixtures("clean_gen_templates")
def test_without_cni_in_sriov_nad(base_fixture):
    resource_name = get_sriov_pf()
    nad_config_manifest = lib_helper.get_sriov_nad_config_manifest(
        'sriov.jsonnet', SRIOV_NAD_NAME)
    nad_config_manifest = remove_cni_from_nad_config(nad_config_manifest)
    nad_input = {
        'name': SRIOV_NAD_NAME,
        'namespace': 'default',
        'annotations': 'openshift.io/' + resource_name,
        'config': json.dumps(nad_config_manifest),
        'template': NAD_TEMPLATE
    }
    lib.create_resource_from_template(nad_input, base_fixture)

    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_nfnas(kapi)
    assert vlans, ("no VLAN information present in NFNA creation")

    pods = create_pods(nad_input["name"], SRIOV_CNI, base_fixture)
    add_vlan_type_interfaces_and_verify_traffic(pods, vlans[0],
                                                vlans[0], base_fixture,
                                                sriov_cni_used=True)
'''

@pytest.mark.usefixtures("clean_gen_templates")
def test_bridge_cni_l2_mode_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    try:
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L2_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], BRIDGE_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[1], base_fixture)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_bridge_cni_l2_mode_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    try:
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L2_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], BRIDGE_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[2], base_fixture)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_bridge_cni_l3_mode_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    try:
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L3_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], BRIDGE_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[1], base_fixture)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_bridge_cni_l3_mode_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    try:
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L3_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], BRIDGE_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[2], base_fixture)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_ipvlan_cni_tagged_mode(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'vlan', IPVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', IPVLAN_NAD_NAME, interface_name,
               'vlan', vlans)

    ns_input = {
        'name': 'ipvlan-test',
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    try:
        nad_config_manifest = lib_helper.get_ipvlan_nad_config_manifest(
            'ipvlan.jsonnet', IPVLAN_NAD_NAME, L2_MODE, interface_name)
        nad_input = {
            'name': IPVLAN_NAD_NAME,
            'namespace': 'ipvlan-test',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], IPVLAN_CNI, base_fixture,
                           namespace='ipvlan-test')
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
            vlans[1], base_fixture, namespace='ipvlan-test',
            nad_name=IPVLAN_NAD_NAME, use_default_ips=False,
            configure_interfaces=False)
    except Exception:
        raise
    finally:
        setup_nncp(nncp_name, 'absent', IPVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_ipvlan_cni_untagged_mode(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'vlan', IPVLAN_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', IPVLAN_NAD_NAME, interface_name,
               'vlan', vlans)

    ns_input = {
        'name': 'ipvlan-test',
        'template': 'namespace.yaml'
    }
    lib.create_resource_from_template(ns_input, base_fixture)

    try:
        nadvlanmap = kapi.get_detail('nadvlanmap', namespace=CONFIGMAP_NAMESPACE)

        if nadvlanmap['items']:
            new_nadvlanmap_config = {
                'ipvlan-test/' + IPVLAN_NAD_NAME : [
                    {
                        'label': IPVLAN_NAD_NAME,
                        'vlans': str(vlans[1])
                    }
                ]
            }
            lib.add_nadvlanmapping(CONFIGMAP_NAMESPACE, new_nadvlanmap_config)
        else:
            new_nadvlanmap_config = {
                'name': 'nad-vlan-map',
                'nad_prefix': IPVLAN_NAD_NAME,
                'namespace': 'ipvlan-test',
                'network_name': IPVLAN_NAD_NAME,
                'vlans': str(vlans[1]),
                'template': NAD_VLAN_MAP_CR_TEMPLATE
            }
            lib.apply_resource_from_template(new_nadvlanmap_config)

        untagged_interface_name = interface_name.split('.')[0]
        nad_config_manifest = lib_helper.get_ipvlan_nad_config_manifest(
            'ipvlan.jsonnet', IPVLAN_NAD_NAME, L2_MODE, untagged_interface_name)
        nad_input = {
            'name': IPVLAN_NAD_NAME,
            'namespace': 'ipvlan-test',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], IPVLAN_CNI, base_fixture,
                           namespace='ipvlan-test')
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
            vlans[1], base_fixture, namespace='ipvlan-test',
            nad_name=IPVLAN_NAD_NAME, use_default_ips=False,
            configure_interfaces=False)
    except Exception:
        raise
    finally:
        lib.remove_nadvlanmapping(CONFIGMAP_NAMESPACE,
                                  'ipvlan-test/' + IPVLAN_NAD_NAME )
        setup_nncp(nncp_name, 'absent', IPVLAN_NAD_NAME, interface_name,
                   'vlan', vlans)
        delete_nncp(nncp_name)


'''@pytest.mark.usefixtures("clean_gen_templates")
def test_ovs_cni_same_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    host_ovs_cni_image_name = prepare_image_name('ovs_cni')
    lib.update_image_in_host_daemonset('aci-containers-host',
                                       host_ovs_cni_image_name)

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'ovs-bridge', OVS_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', OVS_NAD_NAME, interface_name,
               'ovs-bridge')

    try:
        nad_config_manifest = lib_helper.get_ovs_nad_config_manifest(
            'ovs.jsonnet', OVS_NAD_NAME, vlans[0], vlans[1], vlans[2])
        nad_input = {
            'name': OVS_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], OVS_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[1], base_fixture)
    except Exception:
        raise
    finally:
        delete_pods()
        setup_nncp(nncp_name, 'absent', OVS_NAD_NAME, interface_name,
                   'ovs-bridge')
        delete_nncp(nncp_name)
        regular_host_image_name = prepare_image_name('regular')
        lib.update_image_in_host_daemonset('aci-containers-host',
                                           regular_host_image_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_ovs_cni_different_encap(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    host_ovs_cni_image_name = prepare_image_name('ovs_cni')
    lib.update_image_in_host_daemonset('aci-containers-host',
                                       host_ovs_cni_image_name)

    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'ovs-bridge', OVS_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', OVS_NAD_NAME, interface_name,
               'ovs-bridge')

    try:
        nad_config_manifest = lib_helper.get_ovs_nad_config_manifest(
            'ovs.jsonnet', OVS_NAD_NAME, vlans[0], vlans[1], vlans[2])
        nad_input = {
            'name': OVS_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], OVS_CNI, base_fixture)
        add_vlan_type_interfaces_and_verify_traffic(pods, vlans[1],
                                                    vlans[2], base_fixture)
    except Exception:
        raise
    finally:
        delete_pods()
        setup_nncp(nncp_name, 'absent', OVS_NAD_NAME, interface_name,
                   'ovs-bridge')
        delete_nncp(nncp_name)
        regular_host_image_name = prepare_image_name('regular')
        lib.update_image_in_host_daemonset('aci-containers-host',
                                           regular_host_image_name)
'''

@pytest.mark.usefixtures("clean_gen_templates")
def test_contract_to_epg_mapping_from_k8s_to_aci(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    # Creating Node Network Configuration Policy (NNCP) for linux bridge
    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    # Creating contract to allow ICMP
    kapi, apic, cluster_info = lib_helper.get_clusters_info()
    filter_entry, filter, contract = lib_helper.create_contract(
       apic, 'allow_icmp', cluster_info['tenant'], prot='icmp')

    try:
        subnet_1 = [
            {'subnet': '10.30.40.1/24'},
        ]
        subnet_2 = [
            {'subnet': '10.30.50.1/24'},
        ]

        epg_details = [{
            'epg_name': 'test_epg1',
            'bd_name': 'test_bd1',
            'subnets': subnet_1,
            'provider_contract_name': ['allow_icmp'],
            'consumer_contract_name': ['allow_icmp'],
            'vlans': vlans[0]
        },
        {
            'epg_name': 'test_epg2',
            'bd_name': 'test_bd2',
            'subnets': subnet_2,
            'provider_contract_name': ['allow_icmp'],
            'consumer_contract_name': ['allow_icmp'],
            'vlans': vlans[1]
        }]
        nfc_input = {
            'name': 'networkfabricconfiguration',
            'vlans': vlans[0],
            'epg_details': epg_details,
            'vrf_name': cluster_info['vrf'],
            'tenant_name': cluster_info['tenant'],
            'template': NFC_CR_TEMPLATE
        }
        lib.create_resource_from_template(nfc_input, base_fixture)

        # Creating Network Attachment Definition (NAD) with bridge CNI
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L2_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        pods = create_pods(nad_input["name"], BRIDGE_CNI, base_fixture)

        p1_name, p2_name = (pods['multitool-1']['metadata']['name'],
                        pods['multitool-2']['metadata']['name'])
        pods[p1_name], pods[p2_name] = (pods.pop('multitool-1'),
                                        pods.pop('multitool-2'))
        pod_ip = {}
        subnet1 = "10.30.40.0/24"
        subnet2 = "10.30.50.0/24"

        pod_ip[p1_name] = str(ipaddress.IPv4Network(subnet1)[4]) + '/24'
        pod_ip[p2_name] = str(ipaddress.IPv4Network(subnet2)[4]) + '/24'

        # Configuring VLAN type sub-interface in each pod
        configure_pod_vlan_iface(p1_name, vlans[0], pod_ip[p1_name],
                                 base_fixture,
                                 source_subnet=subnet1,
                                 dest_subnet=subnet2)
        configure_pod_vlan_iface(p2_name, vlans[1], pod_ip[p2_name],
                                 base_fixture,
                                 source_subnet=subnet2,
                                 dest_subnet=subnet1)
        LOG.info("Testing ping traffic between pods %s %s" % (p1_name,
                                                              p2_name))
        for p_name in [p1_name, p2_name]:
            dst_pod = list({p1_name, p2_name} - {p_name})[0]
            tips = pod_ip[dst_pod].split("/")[0]
            LOG.info("Target pod ips are : %s" % tips)
            lib_helper.check_ping_from_pod(
                p_name, pods[p_name]['metadata']['namespace'], tips,
                target='pod')

        # Removing contracts from NFC EPG contract mapping
        for epg_detail in epg_details:
            epg_detail.pop('provider_contract_name')
            epg_detail.pop('consumer_contract_name')
        nfc_input = {
            'name': 'networkfabricconfiguration',
            'vlans': vlans[0],
            'epg_details': epg_details,
            'vrf_name': cluster_info['vrf'],
            'tenant_name': cluster_info['tenant'],
            'template': NFC_CR_TEMPLATE
        }
        lib.apply_resource_from_template(nfc_input)

        LOG.info("Testing ping traffic between pods %s %s" % (p1_name,
                                                              p2_name))
        for p_name in [p1_name, p2_name]:
            dst_pod = list({p1_name, p2_name} - {p_name})[0]
            tips = pod_ip[dst_pod].split("/")[0]
            LOG.info("Target pod ips are : %s" % tips)
            # Removed ICMP contracts, so traffic should fail
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    p_name, pods[p_name]['metadata']['namespace'], tips,
                    target='pod')
    except Exception:
        raise
    finally:
        # Deleting ICMP contract created above
        lib_helper.delete_contract(
           apic, cluster_info['tenant'], filter_entry, filter, contract)
        # Un-configuring NNCP created for linux-bridge
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        # Deleting NNCP created for linux-bridge
        delete_nncp(nncp_name)


@pytest.mark.usefixtures("clean_gen_templates")
def test_subnet_scope_control_validation(base_fixture):
    kapi, pods = KubeAPI(), {}
    vlans = get_vlans_from_fabricvlanpool(kapi, 'default')
    assert vlans, ("no VLAN information present in fabricvlanpool")

    # Creating Node Network Configuration Policy (NNCP) for linux bridge
    nncp_name, interface_name = prepare_nncp_and_interface_name(
        'linux-bridge', BRIDGE_NAD_NAME, vlans)
    setup_nncp(nncp_name, 'up', BRIDGE_NAD_NAME, interface_name,
               'linux-bridge')

    # Creating contract to allow ICMP
    kapi, apic, cluster_info = lib_helper.get_clusters_info()
    filter_entry, filter, contract = lib_helper.create_contract(
       apic, 'allow_icmp', cluster_info['tenant'], prot='icmp')

    try:
        subnet_1 = [
            {'subnet': '10.30.40.1/24'},
            {'subnet': '10.30.40.2/24', 'scope': ['advertise-externally']},
            {'subnet': '10.30.40.3/24', 'scope': ['shared-between-vrfs']},
            {'subnet': '10.30.40.4/24', 'scope': ['shared-between-vrfs', 'advertise-externally']},
            {'subnet': '10.30.40.5/24', 'control': ['querier-ip'], 'scope': ['shared-between-vrfs']}
        ]
        subnet_2 = [
            {'subnet': '10.30.50.8/24', 'control': ['no-default-svi-gateway'], 'scope': ['advertise-externally']},
            {'subnet': '10.30.50.7/24', 'control': ['no-default-svi-gateway', 'querier-ip']},
            {'subnet': '2001:420:27c1:331::1/64', 'control': ['nd-ra-prefix']},
            {'subnet': '2001:420:27c1:332::1/64', 'scope': ['advertise-externally', 'shared-between-vrfs'], 'control': ['nd-ra-prefix', 'querier-ip', 'no-default-svi-gateway']},
            {'subnet': '2001:420:27c1:333::1/64', 'scope': ['shared-between-vrfs'], 'control': ['nd-ra-prefix', 'no-default-svi-gateway']}
        ]

        # Creating Network Fabric Configuration (NFC)
        # with EPG-Contract mapping
        epg_details = [{
            'epg_name': 'test_epg1',
            'bd_name': 'test_bd1',
            'subnets': subnet_1,
            'provider_contract_name': ['allow_icmp'],
            'consumer_contract_name': ['allow_icmp'],
            'vlans': vlans[0]
        },
        {
            'epg_name': 'test_epg2',
            'bd_name': 'test_bd2',
            'subnets': subnet_2,
            'provider_contract_name': ['allow_icmp'],
            'consumer_contract_name': ['allow_icmp'],
            'vlans': vlans[1]
        }]
        nfc_input = {
            'name': 'networkfabricconfiguration',
            'vlans': vlans[0],
            'epg_details': epg_details,
            'vrf_name': cluster_info['vrf'],
            'tenant_name': cluster_info['tenant'],
            'template': NFC_CR_TEMPLATE
        }
        lib.create_resource_from_template(nfc_input, base_fixture)

        # Creating Network Attachment Definition (NAD) with bridge CNI
        nad_config_manifest = lib_helper.get_bridge_nad_config_manifest(
            'bridge.jsonnet', BRIDGE_NAD_NAME, L2_MODE, vlans[0],
            vlans[1], vlans[2])
        nad_input = {
            'name': BRIDGE_NAD_NAME,
            'namespace': 'default',
            'config': json.dumps(nad_config_manifest),
            'template': NAD_TEMPLATE
        }
        lib.create_resource_from_template(nad_input, base_fixture)

        # Creating an APIC instance
        apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
        apic_host = apic_provision['aci_config']['apic_hosts'][0]
        Apic = APIC(APIC_USERNAME,APIC_PASSWORD,apic_host)

        # tenant and bridge domain names
        tenant_name = cluster_info['tenant']
        bd_name1 = epg_details[0]['bd_name']
        bd_name2 = epg_details[1]['bd_name']
        bd1_subnets1 = Apic.fetch_subnets(tenant_name,bd_name1)
        bd2_subnets2 = Apic.fetch_subnets(tenant_name,bd_name2)

        # Call the comparison function
        are_subnets_equal_1 = compare_apic_subnets_to_input_subnets(bd1_subnets1, subnet_1)
        assert are_subnets_equal_1, ("subnets created on APIC is not matching with subnets_1 under test_bd1")

        are_subnets_equal_2 = compare_apic_subnets_to_input_subnets(bd2_subnets2, subnet_2)
        assert are_subnets_equal_2, ("subnets created on APIC is not matching with subnets_2 under test_bd2")

    except Exception:
        raise
    finally:
        # Deleting ICMP contract created above
        lib_helper.delete_contract(
           apic, cluster_info['tenant'], filter_entry, filter, contract)
        # Un-configuring NNCP created for linux-bridge
        setup_nncp(nncp_name, 'absent', BRIDGE_NAD_NAME, interface_name,
                   'linux-bridge')
        # Deleting NNCP created for linux-bridge
        delete_nncp(nncp_name)
