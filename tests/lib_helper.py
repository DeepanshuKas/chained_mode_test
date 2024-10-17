import json
import time
import pytest
# from scapy.all import *
from datetime import datetime
from uuid import uuid4
import ipaddress
import random

import os
import requests
import yaml
from acitoolkit import AppProfile, BridgeDomain, Context, EPG, OutsideEPG, \
    OutsideL3, Session, Tenant, VmmDomain
from requests_toolbelt import SourceAddressAdapter
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1
import _jsonnet as jsonnet
from dynaconf import settings
from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from acc_pyutils.exceptions import KctlExecutionFailed
from acc_pyutils.utils import log_check_conn, log_manifest, retry
from tests import aci, test_tuneup
from tests.input.cfg import EXTERNAL_IP_POOL, WGET_CONNECTION_TIMEOUT
from tests.input.cfg import (ACI_PREFIX,
                             APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
from tests.template_utils import GEN_TEST_DIR, TEMPLATE_PATH, env

INPUT_DIR = os.path.abspath('tests/input')
DEFAULT_NAMESPACE = settings.DEFAULT_NAMESPACE

LOG = logger.get_logger(__name__)


# Method picked from test_automation
def aci_filter(aci_list, name):
    return [aci_object for aci_object in aci_list
            if aci_object.name == name][0]


class APIC():
    def __init__(self, user, passwd, apic_ip=None, provision_file=None):
        if not apic_ip:
            apic_ip = self.get_apic_ip_from_provision_file(provision_file)
        self.session = Session("https://%s" % apic_ip, uid=user, pwd=passwd)
        resp = self.session.login()
        if not resp.ok:
            LOG.error('Login failed')

    def get_apic_ip_from_provision_file(self, provision_file):
        self.apic_prov = get_apic_provision_input(
            provision_file=provision_file)
        LOG.info("APIC hosts in provision files - %s " % self.apic_prov[
            'aci_config']['apic_hosts'])
        return self.apic_prov['aci_config']['apic_hosts'][0]

    def get_tenant(self, tenant_name):
        tenants = Tenant.get_deep(self.session)
        return aci_filter(tenants, tenant_name)

    def get_vrf(self, vrf_name, tenant_name):
        tenant = self.get_tenant(tenant_name)
        contexts = Context.get(self.session, tenant)
        return aci_filter(contexts, vrf_name)

    def get_l3out(self, l3out_name, tenant_name):
        tenant = self.get_tenant(tenant_name)
        l3_outs = tenant.get_children(only_class=OutsideL3)
        return aci_filter(l3_outs, l3out_name)

    def get_l3out_epg(self, l3out_name, tenant_name, l3out_epg_name):
        l3out = self.get_l3out(l3out_name, tenant_name)
        l3out_epgs = l3out.get_children(only_class=OutsideEPG)
        return aci_filter(l3out_epgs, l3out_epg_name)

    def get_ap(self, tenant_name, ap_name):
        tenant = self.get_tenant(tenant_name)
        aps = tenant.get_children(AppProfile)
        return aci_filter(aps, ap_name)

    def get_epg(self, tenant_name, ap_name, epg_name):
        ap = self.get_ap(tenant_name, ap_name)
        epgs = ap.get_children(EPG)
        return aci_filter(epgs, epg_name)

    def get_epg_bd(self, tenant_name, ap_name, epg_name):
        epg = self.get_epg(tenant_name, ap_name, epg_name)
        return epg.get_bd()

    def get_epg_provided_contracts(self, tenant_name, ap_name, epg_name):
        epg = self.get_epg(tenant_name, ap_name, epg_name)
        return epg.get_all_provided()

    def get_epg_consumed_contracts(self, tenant_name, ap_name, epg_name):
        epg = self.get_epg(tenant_name, ap_name, epg_name)
        return epg.get_all_consumed()

    def get_bds(self, tenant_name):
        tenant = self.get_tenant(tenant_name)
        return tenant.get_children(BridgeDomain)

    def get_bd_detail(self, tenant_name, bd_name):
        bds = self.get_bds(tenant_name)
        bd = aci_filter(bds, bd_name)
        subnets_addr_list = [subnet.addr for subnet in bd.get_subnets()]
        return {
            'name': bd.name,
            'subnets_addr_list': subnets_addr_list,
            }

    def get_vmm_domain(self, domain_name):
        domains = VmmDomain.get(self.session)
        dom = aci_filter(domains, domain_name)
        dom_detail = self.session.get(
            '/api/node/class/vmmDomP.json?query-target-filter=and(eq('
            'vmmDomP.name,"%s"))' % dom.name).json()
        return dom_detail

    # Gets information about controller firmware that is running.
    def get_ctrl_firmware(self):
        apic_ctrl_firmware_detail = self.session.get(
            '/api/node/class/firmwareCtrlrRunning.json?').json()
        return apic_ctrl_firmware_detail

    def get_apic_version(self):
        apic_resp = self.get_ctrl_firmware()
        apic_version = apic_resp['imdata'][0]['firmwareCtrlrRunning']['attributes']['version']
        return apic_version

    # Gets Opflex Device information and returns a list of unique fabric paths.
    def get_opflex_device_fabric_paths(self):
        opflex_detail = self.session.get(
            '/api/node/class/opflexODev.json?').json()
        fab_paths = []
        for op in opflex_detail['imdata']:
            fab_paths.append(op['opflexODev']['attributes']['fabricPathDn'])
        return set(fab_paths)

    # Returns a list of Virtual Port Channels from the fabric paths.
    def get_vpcs_from_fabric_paths(self):
        vpcs = []
        fab_paths = self.get_opflex_device_fabric_paths()
        for path in fab_paths:
            if "/protpaths-" in path:
                vpc = path.split("/pathep-[")
                vpcUnTrimmed = vpc[-1]
                vpcTrimmed = vpcUnTrimmed[:-1]
                vpcs.append(vpcTrimmed)
        return vpcs

    # Returns a list of Port Channels from the fabric paths.
    def get_pcs_from_fabric_paths(self):
        pcs = []
        fab_paths = self.get_opflex_device_fabric_paths()
        for path in fab_paths:
            if "/paths-" in path:
                pc = path.split("/pathep-[")
                pcUnTrimmed = pc[-1]
                pcTrimmed = pcUnTrimmed[:-1]
                pcs.append(pcTrimmed)
        return pcs

    def get_mo_count(self, vmm, cls_name):
        pathf = (
            '/api/class/comp/prov-OpenShift/ctrlr-[{}]-{}' +
            '/injcont/{}.json?&rsp-subtree-include=count').format(
            '{}', '{}', '{}')
        path = pathf.format(vmm, vmm, cls_name)
        resp = self.session.get(path)
        data = json.loads(resp.text)
        moCount = data['imdata'][0]['moCount']['attributes']['count']
        return int(moCount)

    def fetch_subnets(self,tenant_name,bd_name):
        subnet_path = f"/api/node/mo/uni/tn-{tenant_name}/BD-{bd_name}.json?query-target=subtree&target-subtree-class=fvSubnet"
        subnet = self.session.get(subnet_path)
        return subnet.json()['imdata']



@log_check_conn
def check_ping_from_pod(pod, namespace, target_ip, **kwargs):
    kapi = KubeAPI()
    try:
        kapi.kexec(pod,
                   'ping -c5 %s' % target_ip,
                   namespace=namespace,
                   interpreter='sh -c'
                  )
    except KctlExecutionFailed as ex:
        if not kwargs.get('negative_test', False):
            LOG.error("Pod - %s failed to ping - %s . - %s" % (
                pod, target_ip, ex.message))
        else :
            LOG.info("Expected ping failiure!!")
        raise

@retry(no_of_retry=1 if not test_tuneup.get('retries') else test_tuneup[
    'retries'])
def connect_to_svc(ip, svc):
    s = requests.Session()
    s.mount('http://', SourceAddressAdapter(ip))
    response = s.get('http://%s:%s' % (svc['lb_ip'], svc['port']))
    return response.headers['X-Backend-Server']


def check_connectivity(ip, port):
    with requests.Session() as s:
        s.get('http://%s:%s' % (ip, port))


def connect(url):
    with requests.Session() as s:
        LOG.info("Connecting to - %s" % url)
        r = s.get(url, verify=False)
        if r.status_code not in [200, 201]:
            LOG.info('%s Status code %s' % (r.text, r.status_code))


def connect_with_source_ip(source_ip, url):
    with requests.Session() as s:
        s.mount('https://', SourceAddressAdapter(source_ip))
        s.mount('http://', SourceAddressAdapter(source_ip))
        r = s.get(url, verify=False, timeout=WGET_CONNECTION_TIMEOUT)
        if r.status_code not in [200, 201]:
            LOG.info('%s Status code %s' % (r.text, r.status_code))


def dump_template(file_name, content):
    with open(file_name, 'w') as outfile:
        outfile.write(content)
        outfile.write('\n')

def get_random_ip_within_subnet(subnet):
    ip_subnet = ipaddress.ip_network(subnet, strict=False)
    rand_ip = ipaddress.ip_address(
        random.randint(int(ip_subnet.network_address) + 1,
                       int(ip_subnet.broadcast_address) - 2))
    return rand_ip

def get_extern_subnets_from_cm():
    kapi = KubeAPI()
    try:
        config_map = kapi.get_detail('ConfigMap',
                                    name='aci-containers-config',
                                    namespace='aci-containers-system')
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist, aci-containers-config")
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    config_map['data']['controller-config'] = json.loads(config_map['data']['controller-config'])
    extern_static_subnets = config_map['data']['controller-config']["extern-static"]
    extern_dynamic_subnets = config_map['data']['controller-config']["extern-dynamic"]

    return extern_static_subnets, extern_dynamic_subnets

def get_random_ips_from_extern_subnet(extern_dynamic=False):
    ipv4 = ipv6 = None
    extern_static_subnets, extern_dynamic_subnets = get_extern_subnets_from_cm()
    if extern_dynamic:
        extern_subnets = extern_dynamic_subnets
    else:
        extern_subnets = extern_static_subnets
    LOG.info(extern_subnets)
    for subnet in extern_subnets:
        rand_ip = get_random_ip_within_subnet(subnet)
        if rand_ip.version == 4:
            ipv4 = str(rand_ip)
        elif rand_ip.version == 6:
            ipv6 = str(rand_ip)
        else:
            LOG.info("Invalid IP Version")
    return ipv4, ipv6

def get_pod_ip(pod, namespace):
    kapi = KubeAPI()
    pod = kapi.get_detail('pod', pod, namespace)
    return pod['status']['podIP']


def get_pods_by_labels(selectors, namespace=DEFAULT_NAMESPACE):
    kapi = KubeAPI()
    pods = kapi.get_detail(
        'pods',
        labels=','.join(['%s=%s' % (k, v) for k, v in selectors.items()]),
        namespace=namespace)
    pod_list = list()
    for pod in pods['items']:
        pod_list.append((pod['metadata']['name'], pod['status']['podIP'], pod['spec']['nodeName']))
    return pod_list


def get_cluster_node_count():
    kapi = KubeAPI()
    return len(kapi.get_detail('nodes').get('items', []))


def get_node_name_by_ip(node_ip):
    nodes = KubeAPI().get_detail('nodes')
    host = [node['status']['addresses'] for node in nodes['items']
            for add in node['status']['addresses']
            if add['address'] == node_ip][0]
    return [info['address'] for info in host if info['type'] == 'Hostname'][0]


def get_svc_detail(svc_name, namespace='default'):
    kapi = KubeAPI()
    svc = kapi.get_detail('service', name=svc_name, namespace=namespace)
    svc_detail = {
        'name': svc['metadata']['name'],
        'port': svc['spec']['ports'][0]['port'],
        'type': svc['spec']['type']
    }
    if svc['spec']['type'] == 'LoadBalancer':
        lb_ingress = svc['status']['loadBalancer'].get('ingress', None)
        if lb_ingress is not None:
            svc_detail['lb_ip'] = lb_ingress[0]['ip']
        else:
            svc_detail['lb_ip'] = lb_ingress
    else:
        port = svc['spec']['ports'][0]
        svc_detail['port'] = port['nodePort']
    return svc_detail


def get_svc_endpoints_addresses(svc_name, namespace='default'):
    kapi = KubeAPI()
    eps = kapi.get_detail('endpoints', svc_name, namespace)
    return eps['subsets'][0]['addresses']


def is_apic_reachable(apic_ip):
    LOG.info("........ Testing APIC reachability ........")
    # This just validates the APIC server is reachable or not. Nothing more
    # should be interpreted by this
    res = sr1(IP(dst=apic_ip) / TCP(dport=443, flags='S'), timeout=1)
    if res:
        LOG.info(res.summary())
        assert res[TCP].flags == "SA", "APIC - %s not reachable" % apic_ip
        LOG.info("........ APIC is reachable at - %s ........" % apic_ip)
        return True
    LOG.error("........ APIC is not reachable at - %s" % apic_ip)
    return False


def get_apic_provision_input(provision_file):
    with open(provision_file, 'r') as prov_file:
        apic_prov = yaml.load(prov_file, Loader=yaml.SafeLoader)
    return apic_prov


def get_ip_octets(ip):
    return tuple(int(n) for n in ip.split('.'))


def pods_with_no_traffic(svc_name, namespace, pods):
    eps = get_svc_endpoints_addresses(svc_name, namespace)
    deployed_pods = set()
    for ep in eps:
        deployed_pods.add(ep['targetRef']['name'])
    return deployed_pods - pods


def verify_svc_traffic(svc_name, selectors, target_kind, namespace='default',
                       ext_ip_pool=None):
    svc = get_svc_detail(svc_name, namespace)
    pod_hosts = get_hosts_with_pods_filtered_by_labels(selectors)
    if target_kind.lower() == 'deployment':
        _validate_svc_traffic_for_deployment(
            pod_hosts, svc, svc_name, namespace, ext_ip_pool)
    elif target_kind.lower() == 'daemonset':
        _validate_svc_traffic_for_daemonsets(
            svc, svc_name, namespace, ext_ip_pool)
    elif target_kind.lower() == 'nodeport':
        _validate_svc_traffic_for_nodeport(
            pod_hosts, svc, svc_name, namespace, ext_ip_pool
        )
    elif target_kind.lower() == 'traffic_validation':
        _validate_traffic_during_scale_op(svc, ext_ip_pool)


def _validate_svc_traffic_for_deployment(deployment_pod_hosts, svc, svc_name,
                                         namespace, ext_ip_pool):
    pods = set()
    for ip in ext_ip_pool or EXTERNAL_IP_POOL:
        pods.add(connect_to_svc(ip, svc))
    hosts = set(get_pods_host(pods, namespace))
    assert len(hosts) == len(deployment_pod_hosts), (
        "Only these hosts %s received traffic. Hosts with "
        "deployment pods are %s" % (hosts, deployment_pod_hosts))
    LOG.info("Traffic Loadbalancing for service - '%s' verified successfully" %
             svc_name)


def _validate_svc_traffic_for_daemonsets(svc, svc_name, namespace,
                                         ext_ip_pool):
    pods = set()
    for ip in ext_ip_pool or EXTERNAL_IP_POOL:
        pods.add(connect_to_svc(ip, svc))
    assert len(pods) == len(get_svc_endpoints_addresses(
        svc_name, namespace)), (
            "Not all the pods in service - '%s' received traffic. Pods which "
            "did not received traffic are - %s " % (
                svc_name, pods_with_no_traffic(svc_name, namespace, pods)))
    LOG.info("Traffic Loadbalancing for service - '%s' verified successfully" %
             svc_name)


def _validate_svc_traffic_for_nodeport(deployment_pod_hosts, svc, svc_name,
                                       namespace, ext_ip_pool):

    for ip in ext_ip_pool or EXTERNAL_IP_POOL:
        for dest_ip in deployment_pod_hosts:
            svc['lb_ip'] = dest_ip
            connect_to_svc(ip, svc)
    LOG.info("Traffic Loadbalancing for service - '%s' verified successfully" %
             svc_name)


def _validate_traffic_during_scale_op(svc, ext_ip_pool):
    # VK: We are just ensuring that traffic is fine.
    for ip in ext_ip_pool or EXTERNAL_IP_POOL:
        connect_to_svc(ip, svc)


def get_hosts_with_pods_filtered_by_labels(selectors):
    kapi = KubeAPI()
    pods = kapi.get_detail(
        'pods',
        labels=','.join(['%s=%s' % (k, v) for k, v in selectors.items()]))
    return set(pod['status']['hostIP'] for pod in pods.get('items'))


def get_host_ip_of_pod(pod, namespace='default'):
    kapi = KubeAPI()
    pod = kapi.get_detail('pod', pod, namespace=namespace)
    return pod['status']['hostIP']


def get_pods_host(pods, namespace='default'):
    hosts = list()
    for pod in pods:
        hosts.append(get_host_ip_of_pod(pod, namespace))
    return hosts


def getdumps(v):
    return json.dumps(v) if isinstance(v, list) or isinstance(v, dict) else v


def get_nw_policy_manifest(j_file, name, ingress=None, egress=None,
                           target_selector=None, namespace=None,
                           ingress_rules=None, egress_rules=None):
    pol_temp = "%s/%s" % (TEMPLATE_PATH, j_file)
    pol_input = dict(name=name, ingress=ingress, egress=egress,
                     pod_selector=target_selector, namespace=namespace,
                     ingress_rules=ingress_rules, egress_rules=egress_rules)
    return dump_yml(json.loads(jsonnet.evaluate_file(
        pol_temp, tla_codes=format_input(pol_input))), name)


def get_ns_manifest(j_file, name, labels=None):
    ns_temp = "%s/%s" % (TEMPLATE_PATH, j_file)
    ns_input = {'name': name, 'labels': labels}
    return dump_yml(json.loads(jsonnet.evaluate_file(
        ns_temp, tla_codes=format_input(ns_input))), name)


def get_pod_manifest(j_file, name, namespace=None, labels=None, image=None,
                     node=None):
    pod_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    pod_input = {'name': name, 'namespace': namespace, 'labels': labels,
                 'image': image, 'node': node}
    return dump_yml(json.loads(jsonnet.evaluate_file(
        pod_template, tla_codes=format_input(pod_input))), name, kind='pod')


def get_macvlan_nad_config_manifest(j_file, name, mode=None, master=None):
    nad_config_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    nad_config_input = {'name': name, 'mode': mode, 'master': master}
    return json.loads(jsonnet.evaluate_file(
        nad_config_template, tla_codes=format_input(nad_config_input)))


def get_sriov_nad_config_manifest(j_file, name, vlan=0):
    nad_config_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    nad_config_input = {'name': name, 'vlan': vlan}
    return json.loads(jsonnet.evaluate_file(
        nad_config_template, tla_codes=format_input(nad_config_input)))


def get_bridge_nad_config_manifest(j_file, name, bridge_mode,
                                   vlan, min_vlan, max_vlan):
    nad_config_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    nad_config_input = {
        'name': name,
        'mode': bridge_mode,
        'vlan': vlan,
        'min_vlan': min_vlan,
        'max_vlan': max_vlan
    }
    return json.loads(jsonnet.evaluate_file(
        nad_config_template, tla_codes=format_input(nad_config_input)))


def get_ipvlan_nad_config_manifest(j_file, name, ipvlan_mode, master):
    nad_config_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    nad_config_input = {
        'name': name,
        'mode': ipvlan_mode,
        'master': master,
    }
    return json.loads(jsonnet.evaluate_file(
        nad_config_template, tla_codes=format_input(nad_config_input)))


def get_ovs_nad_config_manifest(j_file, name, vlan, min_vlan, max_vlan):
    nad_config_template = "%s/%s" % (TEMPLATE_PATH, j_file)
    nad_config_input = {
        'name': name,
        'vlan': vlan,
        'min_vlan': min_vlan,
        'max_vlan': max_vlan
    }
    return json.loads(jsonnet.evaluate_file(
        nad_config_template, tla_codes=format_input(nad_config_input)))


def get_clusters_info():
    '''
    Gets the cluster info
    kapi, apic, apic_provision
    '''
    kapi = KubeAPI()
    apic_provision = get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = get_resource_details_from_acc_provision_input_file(
          apic_provision)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, APIC_USERNAME, APIC_PASSWORD)
    return kapi, apic, cluster_info


def create_contract(apic, name, tenant_name, provider_epg=None,
                     consumer_epg=None, prot='unspecified',
                     dToPort='unspecified'):
    '''
    Creates the contract

    Args:
    apic(obj): apic object to access apic
    name(str): contract name
    tenant_name(str): tenant name
    provider_epg(obj): provider epg object
    consumer_epg(obj): consumer epg object
    prot(str): protocol
    dToPort(str): destination port

    '''
    LOG.info("Creating contract %s" % name)
    kube_tenant = apic.get_tenant(tenant_name)
    contract = apic.create_contract(name, kube_tenant)
    filter_entry = apic.create_filter_entry(name, contract,
                                      kube_tenant, prot=prot, dToPort=dToPort)

    if provider_epg:
        apic.provide(provider_epg, contract)
    if consumer_epg:
        apic.consume(consumer_epg, contract)

    filter = name
    LOG.info("Contract %s created" % name)
    return filter_entry, filter, contract


def delete_contract(apic, tenant, filter_entry, filter, contract,
                     provider_epg=None, consumer_epg=None):
    '''
    Deletes the contract
    Args:
    apic(obj): apic object to access apic
    tenant(str): tenant name
    provider_epg(obj): provider epg object
    consumer_epg(obj): consumer epg object
    filter_entry(obj): filter entry object
    filter(str): filter name
    contract(obj): contract object
    '''
    LOG.info("Deleting contract %s" % contract.name)
    kube_tenant = apic.get_tenant(tenant)
    if consumer_epg:
        apic.dont_consume(consumer_epg, contract)
    if provider_epg:
        apic.dont_provide(provider_epg, contract)
    apic.delete_filter_entry(filter_entry)
    apic.delete_filter(filter + "_Filter", kube_tenant)
    # Updating the contract object, so the relations
    # With filter will be removed in the updated contract object
    # Otherwise, deleting the contract object will create filter.
    contract = apic.get_contract_from_tenant(kube_tenant, contract.name)
    apic.delete_contract(contract)
    LOG.info("Deleted contract %s" % contract.name)


def format_input(pol_input):
    return {
        k: json.dumps(getdumps(v)) for k, v in pol_input.items() if v
    }


@log_manifest
def dump_yml(content, name, kind=None):
    out = get_template_file(name)
    with open(out, 'w') as out_f:
        yaml.dump(content, out_f, default_flow_style=False)
    return out


def get_template_file(name):
    if not os.path.exists(GEN_TEST_DIR):
        os.mkdir(GEN_TEST_DIR)
    name = name.replace('-', '_')
    file_name = ''.join((name,
                         datetime.now().strftime('_%Y%m%d_%H%M%S'),
                         str(uuid4()).split('-')[0],
                         '.yaml'))
    return GEN_TEST_DIR + '/%s' % file_name


def get_resource_details_from_acc_provision_input_file(apic_provision):
    aci_config = apic_provision['aci_config']
    use_kube_naming_convention = False
    if 'tenant' in aci_config:
        tenant = aci_config['tenant']['name']
    else:
        tenant = aci_config['system_id']
    if 'use_legacy_kube_naming_convention' in aci_config:
        if aci_config['use_legacy_kube_naming_convention']:
            app_profile = 'kubernetes'
            use_kube_naming_convention = True
        else:
            app_profile = ACI_PREFIX + '-' + aci_config['system_id']
    else:
        app_profile = ACI_PREFIX + '-' + aci_config['system_id']

    return {
            'tenant': tenant,
            'system_id': aci_config['system_id'],
            'app_profile': app_profile,
            'use_kube_naming_convention': use_kube_naming_convention,
            'l3out': aci_config['l3out']['name'],
            'vrf': aci_config.get('vrf', {}).get('name', ''),
            'ext_net': aci_config['l3out']['external_networks'][0]
    }


def get_template(temp_input, gen_template_name):
    template = env.get_template(temp_input['template'])
    rend_template = template.render(input=temp_input)
    template_name = gen_template_name(temp_input['name'])
    dump_template(template_name, rend_template)
    return template_name


def get_pod_details_by_labels(selectors, namespace=DEFAULT_NAMESPACE):
    kapi = KubeAPI()
    pods = kapi.get_detail(
        'pods', labels=','.join(['%s=%s' % (k, v) for k, v in selectors.items()]),
        namespace=namespace)
    pod_list = list()
    for pod in pods['items']:
        pod_list.append((pod['metadata']['name'], pod['metadata']['namespace']))
    return pod_list


def get_pod_details_by_namespace(namespace):
    kapi = KubeAPI()
    pods = kapi.get_detail('pods', namespace=namespace)
    pod_list = list()
    for pod in pods['items']:
        pod_list.append((pod['metadata']['name'], pod['metadata']['namespace']))
    return pod_list


def get_aci_namespace(provision_file=APIC_PROVISION_FILE):
    """Return aci namespace."""
    apic_provision = get_apic_provision_input(provision_file)
    # get cluster info from acc provison input file
    cluster_info = get_resource_details_from_acc_provision_input_file(apic_provision)
    aci_namespace = 'kube-system' if cluster_info.get(
        'use_kube_naming_convention') else 'aci-containers-system'
    return aci_namespace


def connect_to_lbs(external_ip, svc, namespace, timeout):
    s = requests.Session()
    s.mount("http://", SourceAddressAdapter(external_ip))
    LOG.info("Testing LBS : %s in ns %s : EXT[%s] --> http://%s:%s"
        % (svc["name"], namespace, external_ip, svc["lb_ip"], svc["port"]))
    try:
        response = s.get("http://%s:%s" % (svc["lb_ip"], svc["port"]), timeout=timeout)
    except requests.ConnectTimeout as e:
        # This is expected for check_no_lbs_conn_from_ext_ip
        LOG.warning("Unable to connect to service %s - %s" % (svc["name"], e))
        raise


def check_lbs_conn_from_ext_ip(name, namespace, timeout=60):
    """Verify connectivity from external IP to LBS
    :param name : Service name to which connectivity tested
    :param namespace : Service namespace
    :param timeout : Connection timeout"""
    svc = get_svc_detail(name, namespace)
    for ext_ip in EXTERNAL_IP_POOL:
        connect_to_lbs(ext_ip, svc, namespace, timeout)


def check_no_lbs_conn_from_ext_ip(name, namespace, timeout=60):
    """Verify no connectivity from external IP to LBS
    :param name : Service name to which connectivity tested
    :param namespace : Service namespace
    :param timeout : Test duration"""

    max_time = time.time() + timeout
    LOG.info("Test No Connectivity to LBS Started + + +")
    test_iter = 0
    while True:
        test_iter += 1
        LOG.info("Test iteration %d" % test_iter)
        with pytest.raises(requests.ConnectTimeout):
            check_lbs_conn_from_ext_ip(name, namespace, timeout=10)
        time.sleep(10)
        if time.time() >= max_time:
            break

    LOG.info("Test No Connectivity to LBS Ended + + +")


def get_acc_controller_running_node():
    controller_selector = {'name':'aci-containers-controller'}
    CRD_NAMESPACE = 'aci-containers-system'
    pod = get_pods_by_labels(controller_selector, CRD_NAMESPACE)
    assert len(pod) != 0, ("aci-containers-controller pod not found")
    LOG.info("aci-containers-controller running on node %s" % pod[0][2])
    return pod[0][2]

