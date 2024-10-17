import os
import pytest
import time
import random
from subprocess import TimeoutExpired

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from acc_pyutils import exceptions

from tests import aci, lib, lib_helper
from tests.template_utils import env
from tests.input.cfg import (ACI_PREFIX,
                             APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD,
                             ENDPOINT_WAIT_TIME)

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
INTERVAL = 15

def test_annotated_namespace_endpoints(base_fixture, gen_template_name):
    '''
    Launches pod in annotated namespace
    Verifies endpoints in the corresponding EPG
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_name = 'namespace-1'
    try:
        # Creating EPG
        epg = _create_epg(apic, epg_name, cluster_info)
        template = 'annotated_ns.yaml'

        # Creating annotated namespace
        ns_input_1 = {
            'name': 'ns-1',
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_name
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)

        # pod creation within namespace 1
        ns1_pod = lib.create_resource(
            '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        max_time = time.time() + ENDPOINT_WAIT_TIME

        # verify pod's learning source
        # until it timeouts, expected learning source is "learned,vmm"
        while True:
            pod_epg_endpoints = apic.get_endpoints(cluster_info['tenant'],
                                                   cluster_info['app_profile'],
                                                   epg_name, ns1_pod['name'])
            if pod_epg_endpoints:
                if pod_epg_endpoints.lcC == 'learned,vmm':
                    LOG.info("pod [%s] learning source is"
                             " learned,vmm" % ns1_pod['name'])
                    break
            if time.time() >= max_time:
                assert False, "pod[%s] is not learned in epg %s" % (ns1_pod['name'],
                epg_name)
            time.sleep(INTERVAL)
    finally:
        apic.delete_epg(epg)


def test_traffic_with_tcp_contract(base_fixture, gen_template_name):
    '''
    Create pods, service in annotated namespace
    Create allow tcp port contract in apic
    Verify inter_namspace, intra_namespace traffic
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_1 = 'namespace-1'
    epg_2 = 'namespace-2'
    try:
        # Creating epgs
        epg1 = _create_epg(apic, epg_1, cluster_info)
        epg2 = _create_epg(apic, epg_2, cluster_info)

        # Creating annotated namespaces
        template = 'annotated_ns.yaml'
        ns_1_name = 'ns-1'
        ns_2_name = 'ns-2'
        ns_input_1 = {
            'name': ns_1_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_1
        }
        ns_input_2 = {
            'name': ns_2_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_2
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_2)

        client_pod = lib.create_resource(
                 '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        ns1_service_1 = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-1', selector={'role': 'server-1'})
        ns1_service_2 = _deploy_svc(base_fixture, gen_template_name, 'two',
            'ns-1', image='noiro-quay.cisco.com/noiro/openshift-nginx', tport=8081,
            selector={'role': 'server-2'})
        ns2_service_1 = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-2', selector={'role': 'server-1'})
        ns2_service_2 = _deploy_svc(base_fixture, gen_template_name, 'two',
            'ns-2', image='noiro-quay.cisco.com/noiro/openshift-nginx', tport=8081,
            selector={'role': 'server-2'})


        # Create allow tcp contract
        (filter_entry, filter, contract) = _create_contract(apic, 'allow_tcp',
            cluster_info['tenant'], epg2, epg1, prot='tcp',
            dToPort=str(ns2_service_1['spec']['ports'][0]['port']))

        client_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_1_name,
            labels='role=client')['items'])

        # Get host:pod mapping
        ns1_host_pod_map_1 = _host_wise_pod_mapping(
            kapi.get_detail('pods',namespace=ns_1_name,
            labels='role=server-1')['items'])
        # Get host:pod mapping
        ns1_host_pod_map_2 = _host_wise_pod_mapping(
            kapi.get_detail('pods',namespace=ns_1_name,
            labels='role=server-2')['items'])
        ns2_host_pod_map_1 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-1')['items'])

        ns2_host_pod_map_2 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-2')['items'])

        # Intra namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns1_host_pod_map_1,
         ns_1_name)
        _verify_namespace_pod_traffic(client_pod_map, ns1_host_pod_map_2,
         ns_1_name, port=8081)

        _verify_svc_traffic(client_pod_map, ns1_service_1, ns_1_name)
        _verify_svc_traffic(client_pod_map, ns1_service_2, ns_1_name)

        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_1,
            ns_1_name, inter_node_pod_icmp=False, intra_node_pod_icmp=False)
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_2,
            ns_1_name, port=8081, inter_node_pod_icmp=False,
            intra_node_pod_icmp=False, inter_node_pod_http=False,
            intra_node_pod_http=False)
        _verify_svc_traffic(client_pod_map, ns2_service_1, ns_1_name)
        _verify_svc_traffic(client_pod_map, ns2_service_2, ns_1_name,
            to_svc=False)
    finally:
        try:
            _delete_contract(apic, cluster_info['tenant'], epg2,
                             epg1, filter_entry, filter, contract)
        except:
            pass
        try:
            apic.delete_epg(epg2)
        except Exception:
            pass
        try:
            apic.delete_epg(epg1)
        except Exception:
            pass

def test_traffic_with_ip_contract(base_fixture, gen_template_name):
    '''
    Create pods,svc in annotated namespaces
    Create Allow ip contract
    Verify inter_namespace traffic
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_1 = 'namespace-1'
    epg_2 = 'namespace-2'
    try:
        # Creating epgs
        epg1 = _create_epg(apic, epg_1, cluster_info)
        epg2 = _create_epg(apic, epg_2, cluster_info)

        # Creating annotated namespaces
        template = 'annotated_ns.yaml'
        ns_1_name = 'ns-1'
        ns_2_name = 'ns-2'
        ns_input_1 = {
            'name': ns_1_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_1
        }
        ns_input_2 = {
            'name': ns_2_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_2
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_2)

        client_pod = lib.create_resource(
                 '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        ns2_service = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-2', selector={'role': 'server'})

        # Create allow ip contract
        (filter_entry, filter, contract) = _create_contract(apic, 'allow_ip',
                cluster_info['tenant'], epg2, epg1)

        client_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_1_name,
            labels='role=client')['items'])


        ns2_host_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server')['items'])


        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map,
            ns_1_name)
        _verify_svc_traffic(client_pod_map, ns2_service, ns_1_name)
    finally:
        try:
            _delete_contract(apic, cluster_info['tenant'], epg2,
                             epg1, filter_entry, filter, contract)
        except:
            pass
        try:
            apic.delete_epg(epg2)
        except Exception:
            pass
        try:
            apic.delete_epg(epg1)
        except Exception:
            pass

def test_traffic_with_deny_ct(base_fixture, gen_template_name):
    '''
    Create pods, svc in annotated namespaces
    Create allow_ip and deny tcp port contract
    Verify Internamespace traffic
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_1 = 'namespace-1'
    epg_2 = 'namespace-2'
    try:
        # Creating epgs
        epg1 = _create_epg(apic, epg_1, cluster_info)
        epg2 = _create_epg(apic, epg_2, cluster_info)

        # Creating annotated namespaces
        template = 'annotated_ns.yaml'
        ns_1_name = 'ns-1'
        ns_2_name = 'ns-2'
        ns_input_1 = {
            'name': ns_1_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_1
        }
        ns_input_2 = {
            'name': ns_2_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_2
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_2)

        client_pod = lib.create_resource(
                 '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        ns2_service_1 = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-2', selector={'role': 'server-1'})
        ns2_service_2 = _deploy_svc(base_fixture, gen_template_name, 'two',
            'ns-2', image='noiro-quay.cisco.com/noiro/openshift-nginx', tport=8081,
            selector={'role': 'server-2'})

        # Create allow ip contract
        (ip_filter_entry, ip_filter, ip_contract) = _create_contract(apic,
            'allow_ip', cluster_info['tenant'], epg2, epg1)
        # Deny tcp contract
        (tcp_filter_entry, tcp_filter, tcp_contract) = _create_contract(apic,
            'allow_tcp', cluster_info['tenant'], epg2, epg1, prot='tcp',
            dToPort=str(ns2_service_1['spec']['ports'][0]['port']))

        _update_contract_action(apic, cluster_info['tenant'], tcp_contract.name,
            tcp_contract.name+'_Subject', tcp_filter+'_Filter',
            action='deny')

        client_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_1_name,
            labels='role=client')['items'])


        ns2_host_pod_map_1 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-1')['items'])

        ns2_host_pod_map_2 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-2')['items'])

        # REVISIT(NK): In the testcase documentation, it is mentioned expected
        # result for deny contract traffic should succedd, But Itseems it should
        # fail, so this testcase is written expecting the traffic should fail.
        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_1,
            ns_1_name, inter_node_pod_http=False, intra_node_pod_http=False)
        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_2,
            ns_1_name, port=8081)
        _verify_svc_traffic(client_pod_map, ns2_service_1, ns_1_name,
            to_svc=False)
        _verify_svc_traffic(client_pod_map, ns2_service_2, ns_1_name)
    finally:
        try:
            _delete_contract(apic, cluster_info['tenant'], epg2,
                             epg1, tcp_filter_entry, tcp_filter, tcp_contract)
        except Exception:
            pass
        try:
            _delete_contract(apic, cluster_info['tenant'], epg2,
                             epg1, ip_filter_entry, ip_filter, ip_contract)
        except Exception:
            pass

        try:
            apic.delete_epg(epg2)
        except Exception:
            pass
        try:
            apic.delete_epg(epg1)
        except Exception:
            pass

def test_traffic_with_np_without_contract(base_fixture, gen_template_name):
    '''
    Creates pods,svc in annotated namespace
    Create network policy to allow traffic
    Test inter-namespace traffic
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_1 = 'namespace-1'
    epg_2 = 'namespace-2'
    try:
        # Creating epgs
        epg1 = _create_epg(apic, epg_1, cluster_info)
        epg2 = _create_epg(apic, epg_2, cluster_info)

        # Creating annotated namespaces
        template = 'annotated_ns.yaml'
        ns_1_name = 'ns-1'
        ns_2_name = 'ns-2'
        ns_input_1 = {
            'name': ns_1_name,
            'label': 'ns-1',
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_1
        }
        ns_input_2 = {
            'name': ns_2_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_2
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_2)

        # Create pod
        client_pod = lib.create_resource(
                 '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        # Create svc in namespace 2
        ns2_service = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-2', selector={'role': 'server', 'app': 'nginx'})

        # Networkpolicy of namespace 2
        ns2_pol = lib.create_resource(
            '{}/networkpolicy_ns2.yaml'.format(DATA_DIR), base_fixture)

        client_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_1_name,
            labels='role=client')['items'])

        ns2_host_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server')['items'])


        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map,
            ns_1_name, intra_node_pod_icmp=False, intra_node_pod_http=False,
            inter_node_pod_icmp=False, inter_node_pod_http=False)
        _verify_svc_traffic(client_pod_map, ns2_service, ns_1_name,
            to_svc=False)
    finally:
        try:
            apic.delete_epg(epg2)
        except Exception:
            pass
        try:
            apic.delete_epg(epg1)
        except Exception:
            pass


def test_traffic_with_ip_ct_with_np(base_fixture, gen_template_name):
    '''
    Create pods, svc in annotated namespace
    Create network policy and allow ip contract
    Verify internamespace traffic
    '''
    kapi, apic, cluster_info = _get_clusters_info()
    epg_1 = 'namespace-1'
    epg_2 = 'namespace-2'
    try:
        # Creating epgs
        epg1 = _create_epg(apic, epg_1, cluster_info)
        epg2 = _create_epg(apic, epg_2, cluster_info)

        # Creating annotated namespaces
        template = 'annotated_ns.yaml'
        ns_1_name = 'ns-1'
        ns_2_name = 'ns-2'
        ns_input_1 = {
            'name': ns_1_name,
            'label': 'ns-1',
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_1
        }
        ns_input_2 = {
            'name': ns_2_name,
            'tenant': cluster_info['tenant'],
            'app_profile': cluster_info['app_profile'],
            'epg': epg_2
        }
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_1)
        _create_annotated_namespace(base_fixture, gen_template_name,
                                    template, ns_input_2)

        client_pod = lib.create_resource(
                 '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

        ns2_service_1 = _deploy_svc(base_fixture, gen_template_name, 'one',
            'ns-2', selector={'role': 'server-1', 'app': 'nginx'})
        ns2_service_2 = _deploy_svc(base_fixture, gen_template_name, 'two',
            'ns-2', image='noiro-quay.cisco.com/noiro/openshift-nginx', tport=8081,
            selector={'role': 'server-2', 'app': 'nginx'})

        # Networkpolicy of namespace 2
        ns2_pol = lib.create_resource(
            '{}/networkpolicy_ns2.yaml'.format(DATA_DIR), base_fixture)
        # Create allow ip contract
        (filter_entry, filter, contract) = _create_contract(apic, 'allow_ip',
                cluster_info['tenant'], epg2, epg1)

        client_pod_map = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_1_name,
            labels='role=client')['items'])


        ns2_host_pod_map_1 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-1')['items'])
        ns2_host_pod_map_2 = _host_wise_pod_mapping(
            kapi.get_detail('pods', namespace=ns_2_name,
            labels='role=server-2')['items'])

        # Inter namespace traffic
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_1,
            ns_1_name)
        _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_2,
            ns_1_name, port=8081, intra_node_pod_http=False,
            inter_node_pod_http=False)

        _verify_svc_traffic(client_pod_map, ns2_service_1, ns_1_name)
        _verify_svc_traffic(client_pod_map, ns2_service_2, ns_1_name,
            to_svc=False)
    finally:
        try:
            _delete_contract(apic, cluster_info['tenant'], epg2,
                             epg1, filter_entry, filter, contract)
        except:
            pass
        try:
            apic.delete_epg(epg2)
        except Exception:
            pass
        try:
            apic.delete_epg(epg1)
        except Exception:
            pass

def test_traffic_with_tcp_ct_with_np(base_fixture, gen_template_name):
        '''
        Creates the pods, svc in annotated namespaces
        Creates allow tcp contract and network policy
        Verify internamespace traffic
        '''
        kapi, apic, cluster_info = _get_clusters_info()
        epg_1 = 'namespace-1'
        epg_2 = 'namespace-2'
        try:
            # Creating epgs
            epg1 = _create_epg(apic, epg_1, cluster_info)
            epg2 = _create_epg(apic, epg_2, cluster_info)

            # Creating annotated namespaces
            template = 'annotated_ns.yaml'
            ns_1_name = 'ns-1'
            ns_2_name = 'ns-2'
            ns_input_1 = {
                'name': ns_1_name,
                'label': 'ns-1',
                'tenant': cluster_info['tenant'],
                'app_profile': cluster_info['app_profile'],
                'epg': epg_1
            }
            ns_input_2 = {
                'name': ns_2_name,
                'tenant': cluster_info['tenant'],
                'app_profile': cluster_info['app_profile'],
                'epg': epg_2
            }
            _create_annotated_namespace(base_fixture, gen_template_name,
                                        template, ns_input_1)
            _create_annotated_namespace(base_fixture, gen_template_name,
                                        template, ns_input_2)

            client_pod = lib.create_resource(
                     '{}/alpine_pod_ns1.yaml'.format(DATA_DIR), base_fixture)

            ns2_service_1 = _deploy_svc(base_fixture, gen_template_name, 'one',
                'ns-2', selector={'role': 'server-1', 'app': 'nginx'})
            ns2_service_2 = _deploy_svc(base_fixture, gen_template_name, 'two',
                'ns-2', image='noiro-quay.cisco.com/noiro/openshift-nginx', tport=8081,
                selector={'role': 'server-2', 'app': 'nginx'})

            # Networkpolicy of namespace 2
            ns2_pol = lib.create_resource(
                '{}/networkpolicy_ns2.yaml'.format(DATA_DIR), base_fixture)

            (filter_entry, filter, contract) = _create_contract(apic,
                'allow_tcp', cluster_info['tenant'], epg2, epg1, prot='tcp',
                dToPort=str(ns2_service_1['spec']['ports'][0]['port']))

            client_pod_map = _host_wise_pod_mapping(
                kapi.get_detail('pods', namespace=ns_1_name,
                labels='role=client')['items'])


            ns2_host_pod_map_1 = _host_wise_pod_mapping(
                kapi.get_detail('pods', namespace=ns_2_name,
                labels='role=server-1')['items'])
            ns2_host_pod_map_2 = _host_wise_pod_mapping(
                kapi.get_detail('pods', namespace=ns_2_name,
                labels='role=server-2')['items'])

            # Inter namespace traffic
            _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_1,
                ns_1_name, inter_node_pod_icmp=False, intra_node_pod_icmp=False)
            _verify_namespace_pod_traffic(client_pod_map, ns2_host_pod_map_2,
                ns_1_name, port=8081, inter_node_pod_icmp=False,
                intra_node_pod_icmp=False, intra_node_pod_http=False,
                inter_node_pod_http=False)

            _verify_svc_traffic(client_pod_map, ns2_service_1, ns_1_name)
            _verify_svc_traffic(client_pod_map, ns2_service_2, ns_1_name,
                to_svc=False)
        finally:
            try:
                _delete_contract(apic, cluster_info['tenant'], epg2,
                                 epg1, filter_entry, filter, contract)
            except:
                pass
            try:
                apic.delete_epg(epg2)
            except Exception:
                pass
            try:
                apic.delete_epg(epg1)
            except Exception:
                pass

def _get_clusters_info():
    '''
    Gets the cluster info
    kapi, apic, apic_provision
    '''
    kapi = KubeAPI()
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, APIC_USERNAME, APIC_PASSWORD)
    return kapi, apic, cluster_info

def _host_wise_pod_mapping(pods):
    '''
    get all pod details and map them to their respective hosts

    Args:
    pods(list): list of pods info

    Returns:
    dict: dict of pod info in each host_ip

    '''
    host_wise_pods = {}
    for p in pods:
        host_ip = p['status']['hostIP']
        pod_name = p['metadata']['name']
        pod_ip = p['status']['podIP']
        tmp = host_wise_pods.setdefault(host_ip, list())
        tmp.append({'name':pod_name, 'ip':pod_ip})
    return host_wise_pods


def _create_annotated_namespace(base_fixture, gen_template_name,
                                template, namespace):
    '''
        Creates the annotated namespace
        Args:
        template(str): template file name
        namespace(str): namespace name
        Returns:
        None

    '''
    template = env.get_template(template)
    rend_temp = template.render(input=namespace)
    temp_name = gen_template_name(namespace['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)

def _create_epg(apic, name, cluster_info):
    '''
    Creates the epg

    Args:
    apic(obj): apic object to access apic
    name(str): epg name
    cluster_info(dict): apic cluster info
    '''
    tenant = cluster_info['tenant']
    app_profile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']
    system_id = cluster_info['system_id']

    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'

    kube_tenant = apic.get_tenant(tenant)
    source_epg = apic.get_epg(kube_tenant, source_epg_name, app_profile)
    kube_bd = apic.get_bd_from_epg(source_epg)
    kube_vmm = apic.get_vmm(system_id)
    epg = apic.create_epg(name, kube_tenant, kube_bd,
                          kube_vmm, app_profile)
    LOG.info('CREATE EPG %s IN TENANT %s', name, tenant)
    return epg



def _deploy_svc(base_fixture, gen_template_name, name, namespace,
                tport=8080, image=None, selector=None):
    '''
    Creates deployment and svc

    Args:
    name(str): deployement and svc name prefix
    namespace(str): namespace name
    tport(int): target port of svc and container port for deployment
    image(str): container image name
    selector(dict): key and values for labels
    '''
    (deployment, svc) = _get_input_for_svc_and_deployment(
        name, namespace, tport=tport, image=image, selector=selector)
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    return lib.get_detail('service', svc['name'], namespace=namespace)

def _get_input_for_svc_and_deployment(name, namespace, tport=8080, image=None,
    selector=None):
    '''
    Get input for svc and deployment

    Args:
    name(str): deployement and svc name prefix
    namespace(str): namespace name
    tport(int): target port of svc and container port for deployment
    image(str): container image name
    selector(dict): key and values for labels
    '''
    replicas = lib_helper.get_cluster_node_count()
    deployment = {
        'name': '%s-nginx-deploy' % name,
        'template': 'nginx_deployment_annotated.yaml',
        'kind': 'deployment',
        'replicas': replicas,
        'namespace': namespace,
        'container_port': tport
    }
    svc = {
        'name': '%s-nginx-svc' % name,
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'namespace': namespace,
        'target_port': tport,
        'port': tport
    }
    if selector:
        deployment['selector'] = svc['selector'] = selector

    if image:
        deployment['image'] = image
    return deployment, svc


def _create_contract(apic, name, tenant_name, provider_epg,
                     consumer_epg, prot='unspecified', dToPort='unspecified'):
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
    # Create allow tcp contract
    LOG.info("Creating contract %s" % name)
    kube_tenant = apic.get_tenant(tenant_name)
    contract = apic.create_contract(name, kube_tenant)
    filter_entry = apic.create_filter_entry(name, contract,
                                      kube_tenant, prot=prot, dToPort=dToPort)

    apic.provide(provider_epg, contract)
    apic.consume(consumer_epg, contract)
    filter = name
    LOG.info("Contract %s created" % name)
    return filter_entry, filter, contract


def _delete_contract(apic, tenant, provider_epg, consumer_epg,
                     filter_entry, filter, contract):
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
    apic.dont_consume(consumer_epg, contract)
    apic.dont_provide(provider_epg, contract)
    apic.delete_filter_entry(filter_entry)
    apic.delete_filter(filter + "_Filter", kube_tenant)
    # Updating the contract object, so the relations
    # With filter will be removed in the updated contract object
    # Otherwise, deleting the contract object will create filter.
    contract = apic.get_contract_from_tenant(kube_tenant, contract.name)
    apic.delete_contract(contract)
    LOG.info("Deleted contract %s" % contract.name)

def _update_contract_action(apic, tenant, contract, contract_subject, filter,
 action='deny'):
    '''
    Updates the contract action
    Args:
    apic(obj): apic object
    tenant(str): tenant name
    contract(str): contract name
    contract_subject(str): contract_subject name
    filter(str): filter name
    '''
    url = ('/api/node/mo/uni/tn-{tenant}/brc-{contract}'
    '/subj-{contract_subject}/rssubjFiltAtt-{filter}.json')

    url = url.format(tenant=tenant, contract=contract,
     contract_subject=contract_subject, filter=filter)
    data = {
        "vzRsSubjFiltAtt": {
            "attributes": {
                "action": action,
                "tnVzFilterName": filter
            },
            "children": []
        }
    }
    LOG.info("Updating the contract_subject"
        " %s action to %s " % (contract_subject, action))
    apic.session.push_to_apic(url, data)
    LOG.info("Updated the contract_subject"
        " %s action to %s " % (contract_subject, action))



def _verify_namespace_pod_traffic(client_pod_map, host_pod_map, namespace,
    port=8080, intra_node_pod_icmp=True, inter_node_pod_icmp=True,
    intra_node_pod_http=True, inter_node_pod_http=True):
    """
    Verifies the pod traffic by sending icmp and http traffic to pod

    Args:

    client_pod_map(dict): client_pod info
    host_pod_map(dict): pods in host_ip
    namespace(str): namespace name
    port(int): destination port to verify http traffic
    intra_node_pod_icmp(boolean):
        expected status for icmp traffic to pod in same node
    inter_node_pod_icmp(boolean):
        expected status for icmp traffic to pod in diff node
    intra_node_pod_http(boolean):
        expected status for http traffic to pod in same node
    inter_node_pod_http(boolean):
        expected status for http traffic to pod in diff node
    """

    # Intra node communication
    client_host = list(client_pod_map.keys())[0]
    client_pod = client_pod_map[client_host][0]
    server_host = client_host

    if not host_pod_map.get(server_host):
        LOG.error('There are no server pods in the client_pod_node'
                  'in namespace %s, Unable to verify inter namespcae,'
                  ' intranode communication')
    else:
        server_pod = random.choice(host_pod_map[server_host])
        _verify_pod_traffic(client_pod, server_pod, namespace,port=port,
            to_pod_icmp=intra_node_pod_icmp, to_pod_http=intra_node_pod_http )


    # Inter node communication
    host_pod_map.pop(client_host, None)
    if not host_pod_map:
        LOG.error("All pods were deployed in single host." \
              "So, inter node communication could't be tested.")
    else: # choose a diffrent node
        server_host = random.choice(list(host_pod_map))
        server_pod = random.choice(host_pod_map[server_host])
        _verify_pod_traffic(client_pod, server_pod, namespace,port=port,
            to_pod_icmp=inter_node_pod_icmp, to_pod_http=inter_node_pod_http)


def _verify_pod_traffic(client_pod, server_pod, namespace, port=8080,
    to_pod_icmp=True, to_pod_http=True):
    '''
    Verifies the pod to pod traffic

    Args:
    client_pod(dict): client pod info with host_ips
    server_pod(dict): server pod info
    namespace(str): namespace of client pod
    port(int): destination http port
    to_pod_icmp(boolean):
        Expected traffic status for icmp traffic
    to_pod_http(boolean):
        Expected traffic status for http traffic
    '''
    # Verifes the traffic between pod and pod
    if to_pod_icmp == True:
        lib_helper.check_ping_from_pod(
            client_pod['name'], namespace, server_pod['ip'])
    else:
        with pytest.raises(exceptions.KctlExecutionFailed):
            lib_helper.check_ping_from_pod(
                client_pod['name'], namespace, server_pod['ip'])

    if to_pod_http == True:
        lib.check_nw_connection_from_pod(
            client_pod['name'], client_pod['ip'],
            [(server_pod['ip'], port)], namespace)
    else:
        with pytest.raises(TimeoutExpired):
            lib.check_no_nw_connection_from_pod(
                client_pod['name'], client_pod['ip'],
                [(server_pod['ip'], port)], namespace)



def _verify_svc_traffic(client_pod_map, service, namespace, to_svc=True):
    '''
    verifies the traffic from pod to svc

    Args:
    client_pod_map(dict): client_pod info with host_ip
    service(dict): service info
    to_svc(boolean): Expected traffic status to svc
    '''
    # Verifies the traffic between pod and service
    client_host = list(client_pod_map.keys())[0]
    client_pod = client_pod_map[client_host][0]
    svc_ip = service['spec']['clusterIP']
    svc_port = service['spec']['ports'][0]['port']
    if to_svc == True:
        lib.check_nw_connection_from_pod(
            client_pod['name'], client_pod['ip'],
            [(svc_ip, svc_port)], namespace)
    else:
        with pytest.raises(TimeoutExpired):
            lib.check_no_nw_connection_from_pod(
                client_pod['name'], client_pod['ip'],
                [(svc_ip, svc_port)], namespace)
