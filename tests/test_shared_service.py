# This module contains shared service tests
# Below are the test.
# Test 1:
#       Access ext service running in common tenant from a pod
#       in different vrf/tenant
# Test 2:
#       Access ext service running in common tenant from a
#       VM in a different vrf/tenant
# Test 3:
#       Access ext service running in common tenant from an
#       external router of different vrf/tenant
#
import os
import pytest
import sys

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import aci
from tests.input import cfg
from tests import lib
from tests import lib_helper

# Verifying the availability of shared_svc_cfg.py file
ss_cfg = pytest.importorskip("tests.input.shared_svc_cfg",
                             reason="Failed importing shared_svc_cfg")

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
KUBE_NODE_EPG = 'kube-nodes'
KUBE_DEFAULT_EPG = 'kube-default'
KUBE_NODE_BD = 'kube-node-bd'
KUBE_POD_BD = 'kube-pod-bd'
EXT_SUBNET_SCOPE = 'import-security,shared-rtctrl'


@pytest.fixture(scope="module")
def get_clusters_info():
    kapi = KubeAPI()
    apic_provision_c1 = lib_helper.get_apic_provision_input(
        cfg.APIC_PROVISION_FILE)
    apic_provision_c2 = lib_helper.get_apic_provision_input(
        ss_cfg.APIC_PROVISION_FILE_CLUSTER_2)

    # get cluster 1 info from acc provison input file of cluster 1
    c1_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision_c1)
    # get cluster 2 info from acc provison input file of cluster 2
    c2_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision_c2)
    apic_host = apic_provision_c1['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, cfg.APIC_USERNAME, cfg.APIC_PASSWORD)
    return kapi, apic, c1_info, c2_info


@pytest.mark.usefixtures("clean_gen_templates")
def test_shared_service_test_1(base_fixture, get_clusters_info,
                               gen_template_name):
    """Access ext service running in common tenant from a pod in different tenant.

    steps:
    1) Launch service with service contract scope as global
    2) Add the consumed relationship to "kube-default" EPG of second
       cluster to consume the service contract from first cluster.
    3) Change the "kube-pod-bd" (of cluster2) subnet's flag
       from "Private to VRF" to "Shared across VRFs
    4) Launch client pod in cluster 2 and verify reachability of service
    """
    kapi, apic, c1_info, c2_info = get_clusters_info
    deployment = lib.create_resource(
        '{}/nginx_deployment_sample.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'])

    svc1 = lib.create_resource('{}/shared_service.yaml'.format(DATA_DIR),
                               base_fixture)
    svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
    svc_name = svc1['name']
    svc_detail = kapi.get_detail('service',
                                 name=svc_name, namespace=svc_namespace)
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
        )
    cluste1_tenant_obj = apic.get_tenant("common")
    # generate contract name
    resource_suffix = "_svc_" + svc_namespace + "_" + svc1['name']
    contract_name = c1_info['system_id'] + resource_suffix

    tenant = apic.get_tenant(c2_info['tenant'])
    KUBE_DEFAULT_EPG = 'kube-default'
    if not c2_info['use_kube_naming_convention']:
        KUBE_DEFAULT_EPG = cfg.ACI_PREFIX + '-default'
    epg = apic.get_epg(tenant, KUBE_DEFAULT_EPG,
                       app_profile=c2_info['app_profile'])

    contract = apic.get_contract_from_tenant(cluste1_tenant_obj,
                                             contract_name)
    if not contract:
        assert False, "contract [%s] not found" % contract_name

    # set contract for epg "kube-default"
    apic.consume(epg, contract)
    LOG.info(".... contract [%s] set as consumed relationship for"
             " epg [kube-default]" % contract_name)

    if c2_info['use_kube_naming_convention']:
        pod_bd_cluster_2 = KUBE_POD_BD
    else:
        pod_bd_cluster_2 = cfg.ACI_PREFIX + \
            '-' + c2_info['system_id'] + '-pod-bd'
    bd_obj = apic.get_bd(pod_bd_cluster_2, c2_info['tenant'])

    kube_pod_bd_sub_info = apic.get_subnet(c2_info['tenant'], bd_obj)
    if kube_pod_bd_sub_info:
        kube_pod_bd_sub_obj = kube_pod_bd_sub_info[0]
    else:
        assert False, "subnet not found for bd[%s]" % pod_bd_cluster_2

    # store existing kube-pod-bd's subnet scope
    current_subnet_scope = kube_pod_bd_sub_obj.get_scope()
    if current_subnet_scope != "shared":
        apic.set_subnet_scope(kube_pod_bd_sub_obj, "shared")
        LOG.info("..... Set kube-pod-bd's subnet scope from %s to"
                 " shared" % current_subnet_scope)

    service_ip = svc_detail['status']['loadBalancer']['ingress'][0]['ip']
    service_port = svc_detail['spec']['ports'][0]['port']
    targets = [(service_ip, service_port)]
    cluster2_client_pod = None
    # save cluster1 kubeconfig and switch to cluster2
    current_config = os.environ["KUBECONFIG"]
    os.environ["KUBECONFIG"] = ss_cfg.KUBECONFIG_CLUSTER_2
    try:
        # launch pod in second cluster
        cluster2_client_pod = lib.create_resource(
             '{}/busybox_shared_service_client.yaml'.format(DATA_DIR),
             base_fixture)
        lib.check_nw_connection_from_pod(cluster2_client_pod['name'], '',
                                         targets, namespace='default')

    finally:
        # post test cleanup.
        try:
            if cluster2_client_pod:
                # delete the client pod
                kapi.delete(cluster2_client_pod['labels'],
                            cluster2_client_pod['manifest_dir'])
            # revert kube-pod-bd subnet's flag scope
            if current_subnet_scope != "shared":
                apic.set_subnet_scope(kube_pod_bd_sub_obj,
                                      current_subnet_scope)
                LOG.info("..... Revert kube-pod-bd's subnet scope from shared "
                         " to %s" % current_subnet_scope)
            # unset contract for epg "kube-default"
            apic.dont_consume(epg, contract)
            LOG.info(".... Unset consumed contract [%s] for"
                     " epg [kube-default]" % contract_name)
            # revert back to cluste1 config
            os.environ["KUBECONFIG"] = current_config
        except Exception as ex:
            os.environ["KUBECONFIG"] = current_config
            LOG.warning("post test cleaup has failed Reason: %s" % ex)


def test_shared_service_test_2(base_fixture, get_clusters_info):
    """Access ext service running in common tenant from a vm in different tenant.

    steps:
    1) Launch service with service contract scope as global
    2) Add the consumed relationship to "kube-nodes" EPG of second
       cluster to consume the service contract from first cluster.
    3) Change the "kube-node-bd" (of cluster2) subnet's flag
       to "Shared across VRFs
    4) Verify reachability of service from vm launched in second
       cluster.
    """
    kapi, apic, c1_info, c2_info = get_clusters_info
    global KUBE_NODE_EPG
    lib.create_resource(
        '{}/nginx_deployment_sample.yaml'.format(DATA_DIR), base_fixture)

    svc1 = lib.create_resource('{}/shared_service.yaml'.format(DATA_DIR),
                               base_fixture)
    svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
    svc_name = svc1['name']
    svc_detail = kapi.get_detail('service',
                                 name=svc_name, namespace=svc_namespace)
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
        )
    cluste1_tenant_obj = apic.get_tenant("common")
    # generate contract name
    resource_suffix = "_svc_" + svc_namespace + "_" + svc1['name']
    contract_name = c1_info['system_id'] + resource_suffix
    tenant = apic.get_tenant(c2_info['tenant'])

    if not c2_info['use_kube_naming_convention']:
        KUBE_NODE_EPG = cfg.ACI_PREFIX + '-nodes'
    epg = apic.get_epg(tenant, KUBE_NODE_EPG,
                       app_profile=c2_info['app_profile'])
    if not epg:
        assert False, ("EPG [%s] not found for cluster [%s]" % (
            KUBE_NODE_EPG, c2_info['system_id']))

    contract = apic.get_contract_from_tenant(cluste1_tenant_obj,
                                             contract_name)
    if not contract:
        assert False, ("Contract [%s] not found for cluster [%s]" % (
            contract_name, c1_info['system_id']))

    # set contract for epg "kube-nodes"
    apic.consume(epg, contract)
    LOG.info(".... contract [%s] set as consumed relationship for"
             " epg [%s] in tenant [%s]" % (contract_name, KUBE_NODE_EPG,
                                           c2_info['tenant']))

    if c2_info['use_kube_naming_convention']:
        node_bd_cluster_2 = KUBE_NODE_BD
    else:
        node_bd_cluster_2 = cfg.ACI_PREFIX + \
            '-' + c2_info['system_id'] + '-node-bd'
    bd_obj = apic.get_bd(node_bd_cluster_2, c2_info['tenant'])
    kube_node_bd_sub_info = apic.get_subnet(c2_info['tenant'], bd_obj)
    if kube_node_bd_sub_info:
        kube_node_bd_sub_obj = kube_node_bd_sub_info[0]
    else:
        assert False, "subnet not found for bd[%s]" % node_bd_cluster_2

    # store existing kube-pod-bd's subnet scope
    current_subnet_scope = kube_node_bd_sub_obj.get_scope()
    if current_subnet_scope != "shared":
        apic.set_subnet_scope(kube_node_bd_sub_obj, "shared")
        LOG.info("..... Set kube-pod-bd's subnet scope from %s to"
                 " shared" % current_subnet_scope)

    svc_ip = svc_detail['status']['loadBalancer']['ingress'][0]['ip']
    svc_port = svc_detail['spec']['ports'][0]['port']
    try:
        if ss_cfg.ROUTE_ADD_REQUIRED:
            cmd = 'sudo ip route add %s via %s dev %s' % (
                ss_cfg.EXT_SERVICE_SUBNET,
                ss_cfg.NODE_NET_GW,
                ss_cfg.NODE_NET_INF)
            lib.run_command_remotely(ss_cfg.CLUSTER2_TEST2_VM_IP,
                                     ss_cfg.CLUSTER2_TEST2_VM_USERNAME,
                                     ss_cfg.CLUSTER2_TEST2_VM_PASSWORD, cmd)
        lib.validate_datapath(ss_cfg.CLUSTER2_TEST2_VM_IP,
                              ss_cfg.CLUSTER2_TEST2_VM_USERNAME,
                              ss_cfg.CLUSTER2_TEST2_VM_PASSWORD,
                              svc_ip, svc_port)
    finally:
        # post test cleanup.
        try:
            # revert kube-pod-bd subnet's flag scope
            if current_subnet_scope != "shared":
                apic.set_subnet_scope(kube_node_bd_sub_obj,
                                      current_subnet_scope)
                LOG.info("..... Revert kube-node-bd's subnet scope from shared"
                         " to %s" % current_subnet_scope)
            # unset contract for epg "kube-nodes"
            apic.dont_consume(epg, contract)
            LOG.info(".... Unset consumed contract [%s] for"
                     " epg [%s]" % (contract_name, KUBE_NODE_EPG))
            if ss_cfg.ROUTE_ADD_REQUIRED:
                cmd = 'sudo ip route del %s via %s dev %s' % (
                    ss_cfg.EXT_SERVICE_SUBNET,
                    ss_cfg.NODE_NET_GW,
                    ss_cfg.NODE_NET_INF)
                lib.run_command_remotely(ss_cfg.CLUSTER2_TEST2_VM_IP,
                                         ss_cfg.CLUSTER2_TEST2_VM_USERNAME,
                                         ss_cfg.CLUSTER2_TEST2_VM_PASSWORD,
                                         cmd)
        except Exception as ex:
            LOG.warning("post test cleaup has failed Reason: %s" % ex)
            pass


def test_shared_service_test_3(base_fixture, get_clusters_info):
    """Access ext service running in common tenant from ext router in different tenant.

    steps:
    1) Launch service with service contract scope as global
    2) Add the consumed relationship to outside EPG of L3Router
       of second cluster to consume the service contract from
       first cluster.
    3) Add subnet scope "Shared Route Control Subnet" to external
       subnet of outside epg of l3out of cluster2.
    4) verify reachability of service from ext router of second cluster.
    """
    kapi, apic, c1_info, c2_info = get_clusters_info

    lib.create_resource(
        '{}/nginx_deployment_sample.yaml'.format(DATA_DIR), base_fixture)

    svc1 = lib.create_resource('{}/shared_service.yaml'.format(DATA_DIR),
                               base_fixture)
    svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
    svc_name = svc1['name']
    svc_detail = kapi.get_detail('service',
                                 name=svc_name, namespace=svc_namespace)
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
        )
    cluste1_tenant_obj = apic.get_tenant("common")
    # generate contract name
    resource_suffix = "_svc_" + svc_namespace + "_" + svc1['name']
    contract_name = c1_info['system_id'] + resource_suffix
    outside_epg = c2_info['ext_net']

    epg = apic.get_outside_epg_for_l3out(c2_info['l3out'],
                                         outside_epg,
                                         "common")
    if not epg:
        assert False, ("outside epg [%s] not found for l3out [%s] for "
                       " tenant common]" % (outside_epg,
                                            c2_info['l3out']))

    contract = apic.get_contract_from_tenant(cluste1_tenant_obj,
                                             contract_name)
    if not contract:
        assert False, "contract [%s] not found" % contract_name

    apic.set_contract(epg, contract, "common", c2_info['l3out'])
    LOG.info(".... contract [%s] set as consumed relationship for"
             " epg [%s]" % (contract_name, epg.name))

    # get existing scope of external subnet
    curr_sub_scope = apic.get_scope_for_ext_subnet(
        c2_info['l3out'],
        outside_epg,
        "common",
        name=ss_cfg.EXT_SUBNET_NAME_CLUSTER_2,
        ip=ss_cfg.EXT_SUBNET_IP_CLUSTER_2)
    if curr_sub_scope != EXT_SUBNET_SCOPE:
        apic.set_scope_for_ext_subnet(c2_info['l3out'], outside_epg,
                                      "common",
                                      EXT_SUBNET_SCOPE,
                                      name=ss_cfg.EXT_SUBNET_NAME_CLUSTER_2,
                                      ip=ss_cfg.EXT_SUBNET_IP_CLUSTER_2)

    svc_ip = svc_detail['status']['loadBalancer']['ingress'][0]['ip']
    svc_port = svc_detail['spec']['ports'][0]['port']
    try:
        lib.validate_datapath(ss_cfg.CLUSTER2_EXT_ROUTER_NODE_IP,
                              ss_cfg.CLUSTER2_EXT_ROUTER_NODE_USERNAME,
                              ss_cfg.CLUSTER2_EXT_ROUTER_NODE_PASSWORD,
                              svc_ip, svc_port,
                              ss_cfg.CLUSTER2_L3OUT_INTERFACE_IP)
    finally:
        # revert back config to previous state
        try:
            # unset the contract
            apic.unset_contract(epg, contract, "common", c2_info['l3out'])
            LOG.info(".... Unset contract [%s] for"
                     " epg [%s]" % (contract_name, epg.name))
            # revert ext subnet scope to it's previous scope
            if curr_sub_scope != EXT_SUBNET_SCOPE:
                apic.set_scope_for_ext_subnet(
                    c2_info['l3out'], outside_epg,
                    "common", curr_sub_scope,
                    name=ss_cfg.EXT_SUBNET_NAME_CLUSTER_2,
                    ip=ss_cfg.EXT_SUBNET_IP_CLUSTER_2)
        except Exception as ex:
            LOG.warning("post test cleaup has failed Reason: %s" % ex)
            pass
