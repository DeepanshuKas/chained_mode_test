import ipaddress
import json
import os
import random
import socket
import string
import subprocess
import uuid
from json import JSONEncoder
from datetime import datetime
from pprint import pformat

import binascii
import paramiko
import pcapkit
import sys
import time
import yaml
from invoke import UnexpectedExit

from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from acc_pyutils.api import KubeAPI
from acc_pyutils.condition import Condition
from acc_pyutils.utils import (copy_updated_yaml, get_dst_for_updated_manifest,
                               log_check_conn_from_node,
                               log_check_conn_from_pod, log_create,
                               log_update_cm, log_validation,
                               retry,
                               wait_for_condition)
from tests import test_tuneup, lib_helper, validate_snat_apic_resource
from tests.input.cfg import (APIC_PROVISION_FILE, APIC_VALIDATION, COLLECT_PROFILING_DATA,
    CRD_NAMESPACE, EP_FILE_PATH, EXTERNAL_IP_POOL, EXTERNAL_LISTENING_PORT,
    EXTERNAL_ROUTER_INTERFACE, EXTERNAL_ROUTER_IP, HTTP_SERVER_VERSION, KUBE_SYSTEM,
    NETPOL_FILE_PATH, NULL_MAC_FILE_SEARCH_STR, PKT_CAPTURE_ENABLED as PCE, PYTHON_EXEC,
    REMOTE_ROUTER, SNAT_FILE_PATH, SVC_FILE_PATH, WGET_CONNECTION_TIMEOUT, WGET_RETIRES)
import tests.input.cfg as cfg
from tests.server_utils import ServerUtils
from tests.lib_helper import dump_template
from tests.template_utils import env
from hashlib import sha256
from typing import List

CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'

# import threading

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')

EP_FILE = EP_FILE_PATH + '/%s'
SNAT_FILE = SNAT_FILE_PATH + '/%s'
SVC_FILE = SVC_FILE_PATH + '/%s'
NETPOL_FILE = NETPOL_FILE_PATH + '/%s'
SRV_UTILS = ServerUtils()
ACC = 'aci-containers-controller'
ACI_PODS = ['aci-containers-host', 'aci-containers-openvswitch']
NODE_WAIT_TIMEOUT = 2000

# subclass JSONEncoder
class DataEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


def create_hash_from_net_pol(np_metadata, np_spec):
    in_str = ingress_str_sorted(np_metadata, np_spec) if np_spec.get('ingress') else ""
    e_str = egress_str_sorted(np_metadata, np_spec) if np_spec.get('egress') else ""
    key = in_str + e_str
    policy_types = np_spec.get('policyTypes', [])
    if not policy_types:
        if np_spec.get('ingress'):
            policy_types.append("Ingress")
        if np_spec.get('egress'):
            policy_types.append("Egress")
    pt_str = "".join(sort_policy_types(policy_types))

    key += pt_str
    return generate_hash(key)

def peers_to_str(peers):
    if not peers:
        return "[]"

    p_str = "["
    for p in peers:
        if p.get('ipBlock', {}):
            ip_block = p['ipBlock']
            p_str += ip_block.get('cidr', '')
            if ip_block.get('except', []):
                p_str += "[except" + "".join(f"-{e}" for e in ip_block['except']) + "]"
            p_str += "+"
    return p_str.rstrip("+") + "]"

def ports_to_str(ports):
    if not ports:
        return "[]"

    p_str = "["
    for p in ports:
        if p.get('protocol', ''):
            p_str += str(p['protocol'])
        else:
            p_str += "TCP"
        p_str += ":" + str(p.get('port', ''))
        p_str += "+"
    return p_str.rstrip("+") + "]"

def egress_str_sorted(np_metadata, np_spec):
    rules = []
    for rule in np_spec.get('egress', []):
        e_str = selectors_to_str(rule.get('to', []), np_metadata['namespace']) + \
                peers_to_str(rule.get('to', [])) + \
                ports_to_str(rule.get('ports', []))
        rules.append(e_str)
    rules.sort()
    e_str = "+".join(rules)
    return e_str


def ingress_str_sorted(np_metadata, np_spec):
    rules = []
    for rule in np_spec.get('ingress', []):
        i_str = selectors_to_str(rule.get('from', []), np_metadata['namespace']) + \
                peers_to_str(rule.get('from', [])) + \
                ports_to_str(rule.get('ports', []))
        rules.append(i_str)
    rules.sort()
    i_str = "+".join(rules)
    return i_str

def sort_policy_types(policy_types):
    return sorted(str(pt) for pt in policy_types)

def selectors_to_str(peers, namespace):
    str_ = ""
    for p in peers:
        pod_sel = label_selector_to_str(p.get('podSelector', None))
        ns_sel = label_selector_to_str(p.get('namespaceSelector', None))
        str_ += pod_sel + (ns_sel if ns_sel else namespace if pod_sel else "")
    return str_

def label_selector_to_str(label_selector):
    if label_selector is None:
        return ""

    str_ = "["
    match_labels = label_selector.get('matchLabels', {})
    match_expressions = label_selector.get('matchExpressions', [])

    for key in sorted(match_labels):
        str_ += f"{key}_{match_labels[key]}"

    for expr in sorted(match_expressions, key=lambda x: x.get('key', '')):
        str_ += expr.get('key', '') + str(expr.get('operator', ''))
        str_ += "".join(expr.get('values', []))

    return str_ + "]"


def generate_hash(key):
    hash_obj = sha256()
    hash_obj.update(key.encode())
    hash_bytes = hash_obj.digest()[:16]
    hash_str = binascii.hexlify(hash_bytes).decode()
    return hash_str


def check_netpol_file(manifest_file, manifest_dir):
    np_spec = get_resource_spec_from_file(manifest_file)
    np_metadata = get_resource_metadata_from_file(manifest_file)
    np_hash = create_hash_from_net_pol(np_metadata, np_spec)
    netpol_file_name = f"{get_policy_tenant()}_np_{np_hash}.netpol"

    np_namespace = np_metadata["namespace"]
    selector = np_spec.get("podSelector", {}).get("matchLabels", {})
    label_selector = ",".join([f"{key}={value}" for key, value in selector.items()])

    kapi = KubeAPI()
    if label_selector:
        pods = kapi.get_detail("pods", namespace=np_namespace, labels=label_selector)
    else:
        pods = kapi.get_detail("pods", namespace=np_namespace)

    for pod in pods["items"]:
        pod_ip = pod["status"]["podIP"]
        node_name = pod["spec"]["nodeName"]
        LOG.info(
            f"Pod IP: {pod_ip} should be present in netpol file {netpol_file_name} on \
            Node Name: {node_name} in namespace: {np_namespace}"
        )

        if not validate_netpol_file(node_name, netpol_file_name, manifest_dir, pod_ip):
            return False

    return True


@log_create
def create_resource(manifest_file, create_ctxt, manifest_extra_str=None, timeout=None):
    kapi = KubeAPI()
    if 'delete_info' not in create_ctxt:
        create_ctxt['delete_info'] = []
    resource_info = get_resource_metadata_from_file(manifest_file)
    status, label, manifest_dir = kapi.create(manifest_file, manifest_extra=manifest_extra_str, timeout=timeout)
    create_ctxt['delete_info'].append((label, manifest_dir))
    resource_info.update(status=status, add_label=label,
                         manifest_dir=manifest_dir)
    dump_test_meta_info(create_ctxt, manifest_dir)
    assert status is True, '%s %s creation failed.' % (
        resource_info['kind'],
        resource_info.get('name', resource_info.get('generateName')))
    LOG.info('%s - %s created with status - %s . Label - %s  ' % (
        resource_info['kind'],
        resource_info.get('name', resource_info.get('generateName')),
        status, label))
    wait_for_resource_convergence(resource_info['kind'])
    if resource_info['kind'] == 'NetworkPolicy' and is_hpp_direct_enabled():
        LOG.info("Validating netpol files on selected nodes")
        assert check_netpol_file(manifest_file, manifest_dir) is True, "Netpol file validation failed"
    return resource_info


@log_create
def apply_resource(manifest_file):
    kapi = KubeAPI()
    kube_client = get_kube_client()
    resource_info = get_resource_metadata_from_file(manifest_file)
    kapi.exec_cli_cmd(f"{kube_client} apply -f {manifest_file}")
    wait_for_resource_convergence(resource_info['kind'])
    return resource_info


def dump_test_meta_info(create_ctxt, manifest_dir):
    for info in create_ctxt['delete_info']:
        if info[1] == manifest_dir:
            meta_file = get_test_info_file_name(info)
            with open(meta_file, 'w') as m_file:
                m_file.write('--------------------------\n')
                json.dump(create_ctxt['delete_info'], m_file, indent=4)
                m_file.write('\n')


def get_test_info_file_name(info):
    dir_name = info[1] + '/test_info'
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    file_name = dir_name + '/test_info.txt'
    return file_name

def get_ext_router_node_hostname():
    """Returns hostname of manager node."""
    nodes_info = SRV_UTILS.load_nodes_information()
    for node in nodes_info.get('external_router_nodes', []):
        return node['hostname']


def is_rke1_setup():
    """Check if the setup is RKE1 or not."""
    try:
        job_detail = get_detail('jobs', name="rke-network-plugin-deploy-job",\
            namespace="kube-system")
        if job_detail : return True
    except: pass
    LOG.info("It is not a RKE1 Setup")
    return False


def is_rke2_setup():
    """Check if the setup is RKE2 or not."""
    try:
        deployment_detail = get_deployment_details(name="cattle-cluster-agent",\
            namespace="cattle-system")
        if deployment_detail : return True
    except: pass
    LOG.info("It is not a RKE2 setup")
    return False


def get_pod_details(name, namespace='default'):
    kapi = KubeAPI()
    pod_detail = kapi.get_detail('pod', name=name, namespace=namespace)
    uid = pod_detail['metadata']['uid']
    hostname = pod_detail['spec']['nodeName']
    host_ip = pod_detail['status']['hostIP']
    # pod_ip = pod_detail['status']['podIP']
    return uid, host_ip, hostname


def get_deployment_details(name, namespace='default'):
    kapi = KubeAPI()
    deployment = kapi.get_detail('deployment', name=name, namespace=namespace)
    uid = deployment['metadata']['uid']
    match_labels = deployment['spec']['selector']['matchLabels']
    labels = [str(k)+'='+str(v) for k, v in match_labels.items()]
    replicas = deployment['spec']['replicas']
    available_replicas = deployment['status']['availableReplicas']
    return uid, labels, replicas, available_replicas

def get_ds_details(name, namespace='default'):
    kapi = KubeAPI()
    ds = kapi.get_detail('daemonset', name=name, namespace=namespace)
    match_labels = ds['spec']['selector']['matchLabels']
    labels = [str(k)+'='+str(v) for k, v in match_labels.items()]
    return labels


def get_service_details(name, namespace='default'):
    kapi = KubeAPI()
    svc_detail = kapi.get_detail('service', name=name, namespace=namespace)
    uid = svc_detail['metadata']['uid']
    ports = svc_detail['spec']['ports']
    svc_type = svc_detail['spec']['type']
    ingress = svc_detail['status']['loadBalancer']['ingress']
    return uid, ports, svc_type, ingress


def get_temp_dir(dir_name='/tmp'):
    tmp_manifest_dir = "%s/test-spe-%s" % (
        dir_name, datetime.today().strftime('%d_%m_%Y_%H_%M_%S'))
    os.mkdir(tmp_manifest_dir)
    return tmp_manifest_dir


def check_svc_file_if_exists(hostname, svc_uid):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    dest = SVC_FILE % (svc_uid + '.service')
    return server.does_file_exists(dest)


def check_port_allocation_in_snatpolicy(resource, name, namespace='default'):
    condition = Condition(
        'check snatPortAllocated', globals()['is_snatportsallocated'],
        resource, name, namespace)
    wait_for_condition(condition, timeout=30, interval=5)


def check_localinfo_in_localinfo_spec(resource, name, namespace=CRD_NAMESPACE):
    condition = Condition(
        'check localInfo in localInfo spec', globals()[
            'is_localinfo_in_spec'],
        resource, name, namespace)
    wait_for_condition(condition, timeout=180, interval=10)


def check_hostname_in_globalinfo_spec(resource, name, hostname,
                                      namespace=CRD_NAMESPACE):
    condition = Condition(
        'check hostname in globalInfo spec', globals()[
            'is_host_in_globalinfo_spec'],
        resource, name, hostname, namespace)
    wait_for_condition(condition, timeout=180, interval=10)


def check_pod_status(name, labels=None, namespace=KUBE_SYSTEM, timeout=120):
    condition = Condition(
        'check pod status', globals()['is_pod_running'],
        name, labels, namespace)
    wait_for_condition(condition, timeout=timeout, interval=10)


def is_svc_graph_used(apic, graph_name, contract):
    return apic.is_svc_graph_used_for_contract(graph_name, contract)

def check_svc_graph_used(apic, graph_name, contract, timeout=30):
    condition = Condition(
        'check svc graph used for contract', globals()['is_svc_graph_used'],
        apic, graph_name, contract)
    wait_for_condition(condition, timeout=timeout, interval=10)

def is_svc_graph_not_used(apic, graph_name, contract):
    return not apic.is_svc_graph_used_for_contract(graph_name, contract)

def check_svc_graph_not_used(apic, graph_name, contract, timeout=30):
    condition = Condition(
        'check svc graph not used for contract', globals()['is_svc_graph_not_used'],
        apic, graph_name, contract)
    wait_for_condition(condition, timeout=timeout, interval=10)


def check_service_ip(name, namespace):
    condition = Condition('check service clusterIP',
                          globals()['is_cluster_ip_allocated'],
                          name,
                          namespace)
    wait_for_condition(condition, timeout=120, interval=10)


def check_available_deployment_replicas(name, namespace, expected_replica_nos,
                                        timeout=120):
    condition = Condition('check no of available replicas',
                          globals()['check_no_of_replicas'],
                          name,
                          namespace,
                          expected_replica_nos)
    wait_for_condition(condition, timeout=timeout, interval=10)


def check_os_route_status(name, namespace):
    condition = Condition('verify ingress route status',
                          globals()['verify_ingress_route_status'],
                          name,
                          namespace)
    wait_for_condition(condition, timeout=120, interval=10)


def check_aci_containers_image(res_type, res_name, container_name,
                               expected_image_name, namespace,
                               initcontainer=False):
    condition = Condition('verify aci containers image',
                          globals()['verify_aci_containers_image'],
                          res_type,
                          res_name,
                          container_name,
                          expected_image_name,
                          namespace,
                          initcontainer)
    wait_for_condition(condition, timeout=240, interval=10)


def verify_aci_containers_image(res_type, res_name,
                                container_name,
                                expected_image_name,
                                namespace,
                                initcontainer):
    image_name = None
    resource_details = get_detail(res_type, res_name, namespace)
    if initcontainer:
        container_details = resource_details['spec']['template'][
            'spec']['initContainers']
    else:
        container_details = resource_details['spec']['template'][
            'spec']['containers']
    for container in container_details:
        if container['name'] == container_name:
            image_name = container['image'].split(":")[1]

    if image_name == expected_image_name:
        return True
    else:
        return False


def check_aci_related_namespace_exists(namespaces):
    LOG.info("........ Verifying namespaces in cluster ........")
    namespace_list = list()
    for namespace in namespaces['items']:
        if namespace['metadata']['name'] in [CRD_NAMESPACE, KUBE_SYSTEM]:
            namespace_list.append(namespace['metadata']['name'])
    LOG.info("........ %s namespaces exists in cluster ........" %
             namespace_list)
    return 2 == len(namespace_list)


def check_aci_pods(pods):
    aci_pods = list()
    for pod in pods['items']:
        if 'aci' in pod['metadata']['name']:
            try:
                for container_status in pod['status']['containerStatuses']:
                    if not container_status['ready'] or "running" not in \
                            container_status['state']:
                        raise Exception(
                            'Issue with pod - %s . Pod Detail - %r' % (
                                pod['metadata']['name'], pod))
            except KeyError:
                raise Exception('Pod - %s has some issues. %s' %
                                (pod['metadata']['name'], pod))
            aci_pods.append(pod)
    return aci_pods

def poll_for_aci_pods(node):
    """This function polls for the aci pods for the given node till all the containers are in ready state"""
    kapi = KubeAPI()
    start_time = time.time()
    while time.time() - start_time < 300:
        LOG.info("Waiting for ACI pods to be in ready state. . . ")
        ready = False
        pods = kapi.get_detail('pod', namespace='aci-containers-system')
        for pod in pods['items']:
            try:
                if pod['spec']['nodeName'] == node and 'aci' in pod['metadata']['name']:
                    for container_status in pod['status']['containerStatuses']:
                        if container_status['ready'] and "running" in container_status['state']:
                            ready = True
            except Exception as e:
                raise Exception('Pod - %s has some issues. %s' %(pod['metadata']['name'], pod, str(e)))
        if ready:
            LOG.info("All pods in ready state. Time taken for the aci pods to be ready after reboot is %s seconds" % (time.time() - start_time))
            break
        time.sleep(5)
    total_time = time.time() - start_time
    return ready, total_time

def verify_aci_pods_on_all_nodes(aci_pods):
    LOG.info("........ Verifying ACI pods on cluster nodes ........")
    node_pods_assoc = dict()
    for pod in aci_pods:
        _update_node_pods_association(node_pods_assoc, pod)
    verify_aci_pods_on_masters(node_pods_assoc)
    verify_aci_pod_on_workers(node_pods_assoc)
    verify_acc_running_in_cluster(node_pods_assoc)
    LOG.info("........ ACI pod verification completed ........")


def _update_node_pods_association(node_pods_assoc, pod):
    if pod['spec']['nodeName'] not in node_pods_assoc:
        node_pods_assoc[pod['spec']['nodeName']] = []
    node_pods_assoc[pod['spec']['nodeName']].append(
        pod['metadata']['name'])


def verify_aci_pods_on_masters(node_pods_assoc):
    masters = get_master_nodes_hostname()
    for master in masters:
        for pod in ACI_PODS:
            assert pod_exist_in_node(
                pod, master, node_pods_assoc[master]) is True, (
                    "Pod - %s not running on master node - %s" % (pod, master))


def verify_aci_pod_on_workers(node_pods_assoc):
    workers = get_worker_nodes_hostname()
    for worker in workers:
        for pod in ACI_PODS:
            assert pod_exist_in_node(
                pod, worker, node_pods_assoc[worker]) is True, (
                    "Pod - %s not running on worker node - %s" % (pod, worker))


def verify_acc_running_in_cluster(node_pods_assoc):
    nodes = get_master_nodes_hostname() + get_worker_nodes_hostname()
    for node in nodes:
        if pod_exist_in_node(ACC, node, node_pods_assoc[node]):
            return
    raise Exception("aci-container-controller pod not running on any node")


def pod_exist_in_node(pod, node, node_pods):
    for node_pod in node_pods:
        if pod in node_pod:
            LOG.info("%s - running on node - %s" % (node_pod, node))
            return True
    return False


def get_master_nodes_hostname():
    masters = list()
    nodes = get_all('nodes')
    for node in nodes['items']:
        if "node-role.kubernetes.io/master" in node['metadata']['labels']:
            masters.append(node['metadata']['name'])
    return masters


def get_worker_nodes_hostname():
    workers = list()
    nodes = get_all('nodes')
    for node in nodes['items']:
        if "node-role.kubernetes.io/master" not in node['metadata']['labels']:
            workers.append(node['metadata']['name'])
    return workers


def get_master_nodes_hostname_with_ready_state():
    masters = list()
    nodes = get_all('nodes')
    for node in nodes['items']:
        if "node-role.kubernetes.io/master" in \
                node['metadata']['labels'] and check_node_condition(node):
            masters.append(node['metadata']['name'])
    return masters


def get_worker_nodes_hostname_with_ready_state():
    workers = list()
    nodes = get_all('nodes')
    for node in nodes['items']:
        if "node-role.kubernetes.io/master" not in \
                node['metadata']['labels'] and check_node_condition(node):
            workers.append(node['metadata']['name'])
    return workers


def get_all_nodes_hostname_with_ready_state():
    workers = get_worker_nodes_hostname_with_ready_state()
    masters = get_master_nodes_hostname_with_ready_state()
    return workers + masters


def get_all_nodes_count_with_ready_state():
    return len(get_all_nodes_hostname_with_ready_state())

def get_one_of_workers_with_ready_state():
    worker = ""
    workers = get_worker_nodes_hostname_with_ready_state()
    if len(workers) > 0:
        worker = workers[0]
    return worker


def check_node_condition(node):
    for cond in node['status']['conditions']:
        if cond.get('type') == "Ready" and \
                cond.get('status') in ['Unknown', 'False']:
            return False
    return True


def get_verified_snatpolicy(name, namespace='default'):
    check_port_allocation_in_snatpolicy('SnatPolicy', name, namespace)
    return get_detail('SnatPolicy', name, namespace)


def get_detail(resource, name, namespace='default'):
    kapi = KubeAPI()
    return kapi.get_detail(resource, name=name, namespace=namespace)


def get_resource_name_from_file(input_file):
    with open(input_file, 'r') as f:
        resource = yaml.safe_load(f)
    return resource['metadata']['name']

def get_resource_spec_from_file(input_file):
    with open(input_file, 'r') as f:
        resource = yaml.safe_load(f)
    return resource['spec']

def get_resource_metadata_from_file(input_file):
    with open(input_file, 'r') as f:
        resource = yaml.safe_load(f)
        resource['metadata']['kind'] = resource['kind']
    # (VK):
    resource['metadata']['namespace'] = resource['metadata'].get(
        'namespace', 'default')
    return resource['metadata']


def get_ep_file_name_if_exists(hostname, pod_uid):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    return server.search_file_in_directory(EP_FILE_PATH, pod_uid)


def get_qos_ingress_policing_rate_from_file(qos_policy):
    if qos_policy['spec']['ingress']:
        return qos_policy['spec']['ingress']['policing_rate']
    return -1


def get_qos_ingress_policing_burst_from_file(qos_policy):
    if qos_policy['spec']['ingress']:
        return qos_policy['spec']['ingress']['policing_burst']
    return -1


def get_qos_egress_policing_rate_from_file(qos_policy):
    if qos_policy['spec']['egress']:
        return qos_policy['spec']['egress']['policing_rate']
    return -1


def get_qos_egress_policing_burst_from_file(qos_policy):
    if qos_policy['spec']['egress']:
        return qos_policy['spec']['egress']['policing_burst']
    return -1


def get_qos_dscpmark_from_file(qos_policy):
    if qos_policy['spec']['dscpmark']:
        return qos_policy['spec']['dscpmark']
    return -1


def get_snat_file_name_if_exists(hostname, snat_id):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    return server.search_file_in_directory(SNAT_FILE_PATH, snat_id)


def get_snat_ids(hostname, snat_ip_list):
    check_hostname_in_globalinfo_spec(
        'snatglobalinfo', 'snatglobalinfo', hostname, namespace=CRD_NAMESPACE)
    global_infos = get_detail(
        'snatglobalinfo', name='snatglobalinfo', namespace=CRD_NAMESPACE)[
            'spec']['globalInfos']
    # (VK): SNAT IPs in SNAT policy are with subnet mask which is not same
    # as listed in globalinfos where snatIp is without mask.
    ip_list = transform_snat_ips(snat_ip_list)
    return {snat_info['snatIp']: snat_info['snatIpUid']
            for snat_info in global_infos[hostname]
            if snat_info['snatIp'] in ip_list}


def transform_snat_ips(snat_ip_list):
    # (VK): Observed that SNAT IPs are coming with subnet mask
    ips = list()
    for ip in snat_ip_list:
        ips.append(ip.split("/")[0])
    return ips


def get_allocated_snat_ips_from_policy(snat_policy):
    return list(snat_policy['spec']['snatIp']
                if snat_policy['spec']['snatIp']
                else [])


def get_allocated_snat_ips_for_service(svc):
    svc = get_detail('Service', svc['name'], svc.get('namespace', 'default'))
    ips = list()
    for ip_detail in svc['status']['loadBalancer']['ingress']:
        ips.append(ip_detail['ip'])
    return ips


def get_snat_ids_from_policy(snat_policy):
    if not snat_policy or not snat_policy['spec'].get('snatIp'):
        return
    ids = list()
    for ip_detail in snat_policy['spec']['snatIp']:
        ipaddr = ip_detail.split("/")[0]
        ip = ipaddress.ip_address(ipaddr)
        if ip.version == 6:
            ip_bin = socket.inet_pton(socket.AF_INET6, ipaddr)
            hex_str = binascii.hexlify(ip_bin).decode('utf-8')
            uuid_str = '{}-{}-{}-{}-{}'.format(hex_str[:8], hex_str[8:12], hex_str[12:16], hex_str[16:20], hex_str[20:])
        elif ip.version == 4:
            ip_bin = socket.inet_pton(socket.AF_INET, ipaddr)
            hex_str = binascii.hexlify(ip_bin).decode('utf-8')
            uuid_str = "00000000-0000-0000-0000-ffff" + hex_str
        else:
            raise Exception("IP Address %s is invalid" % ipaddr)
        ids.append(uuid_str)
    return ids


def get_snat_ids_for_service(svc):
    svc = get_detail('Service', svc['name'], svc.get('namespace', 'default'))
    ids = list()
    for ip_detail in svc['status']['loadBalancer']['ingress']:
        ipaddr = ip_detail['ip'].split("/")[0]
        ip = ipaddress.ip_address(ipaddr)
        if ip.version == 6:
            ip_bin = socket.inet_pton(socket.AF_INET6, ipaddr)
            hex_str = binascii.hexlify(ip_bin).decode('utf-8')
            uuid_str = '{}-{}-{}-{}-{}'.format(hex_str[:8], hex_str[8:12], hex_str[12:16], hex_str[16:20], hex_str[20:])
        elif ip.version == 4:
            ip_bin = socket.inet_pton(socket.AF_INET, ipaddr)
            hex_str = binascii.hexlify(ip_bin).decode('utf-8')
            uuid_str = "00000000-0000-0000-0000-ffff" + hex_str
        else:
            raise Exception("IP Address %s is invalid" % ipaddr)
        ids.append(uuid_str)
    return ids


def get_dest_ips_from_policy(snat_policy):
    return list(snat_policy['spec']['destIp'])


def get_pcap_file_name(suffix=None):
    if suffix:
        return 'sample-{}.pcap'.format(suffix)
    return 'sample-{}.pcap'.format(str(uuid.uuid4())[0:8])


def is_snatportsallocated(resource, name, namespace='default'):
    snatpolicy = get_detail(resource, name=name, namespace=namespace)
    if 'snatPortsAllocated' in snatpolicy['status']:
        return True
    return False


def is_localinfo_in_spec(resource, name, namespace=CRD_NAMESPACE):
    localinfo = get_detail(resource, name, namespace)
    if 'localInfos' in localinfo['spec']:
        return True
    LOG.info('localInfos not found in localinfo spec of host - %s . '
             'Retrying ... ' % name)
    return False

def get_policy_tenant():
    try:
        config_map = get_detail('ConfigMap',
                                name=CONFIGMAP_NAME,
                                namespace=CONFIGMAP_NAMESPACE)
        controller_config = json.loads(config_map['data']['controller-config'])
        return controller_config['aci-policy-tenant']
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", CONFIGMAP_NAME)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

def is_hpp_direct_enabled():
    try:
        config_map = get_detail('ConfigMap',
                                name=CONFIGMAP_NAME,
                                namespace=CONFIGMAP_NAMESPACE)
        controller_config = json.loads(config_map['data']['controller-config'])
        config_map['data']['controller-config'] = controller_config

        if "enable-hpp-direct" in config_map['data']['controller-config']:
            return controller_config['enable-hpp-direct']
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", CONFIGMAP_NAME)
        assert False, ("Validating config map failed, Reason: %s" % e.message)
    return False

def is_host_in_globalinfo_spec(resource, name, hostname,
                               namespace=CRD_NAMESPACE):
    globalinfo = get_detail(resource, name, namespace)
    if hostname in globalinfo['spec']['globalInfos']:
        return True
    LOG.info('Hostname %s not found in globalinfo spec. Retrying ...' %
             hostname)
    return False


def is_pod_running(name=None, label=None, namespace='default'):
    pods = get_pod_detail(label, name, namespace)
    if not pods:
        return False
    pod_list = pods['items'] if label is not None else pods
    status = list()
    for pod in pod_list:
        if pod['status']['phase'].lower() != "running":
            return False
        for condition in pod['status']['conditions']:
            if condition['type'].lower() != 'ready':
                continue
            status.append(True if condition['status'].lower() == 'true' else False)
    return all(status)


def check_all_pods_running_and_ready(pod_count, namespace='default', selectors={}):
    """This function checks if
    1. number of pods are same as expected
    2. All of the expected pods are running"""

    kapi = KubeAPI()
    label_selector = ",".join(["%s=%s" % (k, v) for k, v in selectors.items()])
    pods = kapi.get_detail('pod', namespace=namespace, labels=label_selector)
    LOG.info("pod_count %d pods len %d selector %s" % (pod_count, len(pods['items']), label_selector))

    start_time = time.time()
    running = False
    # check pod status
    while time.time() - start_time < 300:
        if is_pod_running(label=label_selector, namespace=namespace):
            total_time = time.time() - start_time
            LOG.info("All pods with label %s running state. Time taken to be ready after reboot is %d seconds",
                     label_selector, total_time)
            running = True
            break
        LOG.info("Waiting for pods with label %s to come in ready state", label_selector)
        time.sleep(10)

    pods = kapi.get_detail('pod', namespace=namespace, labels=label_selector)
    LOG.debug("pod_count %d pods len %d selector %s", pod_count, len(pods['items']), label_selector)
    # Check for exact count here since some pods might be in terminating state after reboot
    assert pod_count == len(pods['items']), (f"Pods count {len(pods['items'])} is not equal to the expected number {pod_count}")
    total_time = time.time() - start_time
    return running, total_time


def is_cluster_ip_allocated(name, namespace='default'):
    svc = get_detail('service', name, namespace)
    if not svc['spec']['clusterIP']:
        return False
    return True


def check_no_of_replicas(name, namespace='default', expected_replica_nos=None):
    deployment = get_detail('deployment', name, namespace)
    if not expected_replica_nos:
        return True
    if 'availableReplicas' in deployment['status']:
        if deployment['status']['availableReplicas'] == expected_replica_nos:
            LOG.info("Available no of replicas for deployment %s is %s, "
                     "which matches expectation" % (
                        name, deployment['status']['availableReplicas']))
            return True
        else:
            return False
    else:
        return False


def get_all(kind, namespace=None):
    kapi = KubeAPI()
    if namespace:
        return kapi.get_detail(kind, namespace=namespace)
    return kapi.get_detail(kind)


def get_all_namespaces():
    return get_all('namespaces')


def get_all_pods(namespace):
    return get_all('pods', namespace=namespace)


def get_pod_detail(label, name, namespace):
    kapi = KubeAPI()
    kwargs = {}
    if name:
        return [kapi.get_detail('pod', name, namespace=namespace)]
    if label:
        kwargs['labels'] = label
        return kapi.get_detail('pod', namespace=namespace, **kwargs)
    return []


def kill_server():
    cmd = "for screen in $(screen -ls | grep http-server);" \
          "do screen -S $screen -X quit; done"
    try:
        if REMOTE_ROUTER:
            SRV_UTILS.get_external_router().run(cmd)
        else:
            subprocess.Popen([cmd], shell=True)
    except Exception:
        pass


def launch_simple_server(port):
    if HTTP_SERVER_VERSION < 3 or sys.version_info[0] < 3:
        cmd = "screen -S http-server -dm {} -m SimpleHTTPServer {}".format(
            PYTHON_EXEC, port)
    else:
        cmd = "screen -S http-server -dm {} -m http.server {}".format(
            PYTHON_EXEC, port)
    run_test_server(cmd)
    check_screen_is_running()
    LOG.info('........ Server Started ........')


@retry(no_of_retry=2)
def check_screen_is_running():
    cmd = "screen -ls | grep http-server"
    if REMOTE_ROUTER:
        res = SRV_UTILS.get_external_router().run(cmd)
    else:
        res = subprocess.Popen([cmd], stdout=subprocess.PIPE,
                               shell=True).communicate()[0]
    if "http-server" not in str(res):
        raise Exception("HTTP Server is not running on external router.")


def run_test_server(cmd):
    if REMOTE_ROUTER:
        SRV_UTILS.get_external_router().run(cmd)
    else:
        subprocess.Popen([cmd], shell=True)


def pod_id_exists_in_localinfo(uid, hostname):
    check_localinfo_in_localinfo_spec(
        'snatlocalinfo', hostname, namespace=CRD_NAMESPACE)
    localinfo_detail = get_detail(
        'snatlocalinfo', name=hostname, namespace=CRD_NAMESPACE)
    localinfo_spec = localinfo_detail['spec']['localInfos']
    assert uid in localinfo_spec, (
        'Pod Id - %s does not exists in localinfo - %s . Dump - %s' %
        (uid, hostname, pformat(localinfo_detail)))


def snat_ips_exists_in_localinfo(hostname, snat_policy_name, snat_ips):
    check_localinfo_in_localinfo_spec(
        'snatlocalinfo', hostname, namespace=CRD_NAMESPACE)
    localinfo_detail = get_detail(
        'snatlocalinfo', name=hostname, namespace=CRD_NAMESPACE)
    localinfo_spec = localinfo_detail['spec']['localInfos']
    local_info_ips = [v['snatIp'] for _, v in localinfo_spec.items()
                      if v['snatPolicyName'] == snat_policy_name]
    assert frozenset(snat_ips).issubset(frozenset(local_info_ips)) is True, (
        'Snat IP not found in localinfo - %s . Dump - %s ' %
        (hostname, localinfo_detail))


def snat_ip_exists(info, snat_ips):
    ips = transform_snat_ips(snat_ips)
    if isinstance(snat_ips, list):
        return info['snat-ip'] in ips
    return False


def snat_ip_exists_in_ep(info, snat_ips):
    if isinstance(snat_ips, list):
        # key - 'ip' is different in ep and snat file
        return info['ip'] in snat_ips
    return False


def snat_id_exists(info, snat_ids):
    for snat_id in snat_ids:
        if snat_id not in info['snat-uuids']:
            return False
    return True


def get_ep_file_content(hostname, ep_file, manifest_dir):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    local_ep_file = '%s/%s' % (manifest_dir, ep_file)
    server.get(EP_FILE % ep_file, local_ep_file)
    with open(local_ep_file, 'r') as e:
        ep = json.load(e)
        LOG.info('******** EP file - %s - . Dump - %s '
                 '********' % (ep_file, pformat(ep)))
    return ep


def validate_netpol_file(hostname, netpol_file, manifest_dir, pod_ip):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    local_netpol_file = f"{manifest_dir}/{netpol_file}"
    try:
        server.get(NETPOL_FILE % netpol_file, local_netpol_file)
        with open(local_netpol_file, "r") as e:
            json.load(e)
            if pod_ip in e:
                return True
        return True
    except Exception as e:
        LOG.error(f"Error while retrieving netpol file: {netpol_file} from host {hostname}: {e}")
        return False


def get_svc_file_content(hostname, svc_file, manifest_dir):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    local_svc_file = '%s/%s_%s' % (manifest_dir, hostname, svc_file.split(
        '/')[-1])
    server.get(svc_file, local_svc_file)
    with open(local_svc_file, 'r') as e:
        sv = json.load(e)
        LOG.info('******** Opflex service file - %s - . Dump - %s '
                 '********' % (svc_file, pformat(sv)))
    return sv


def check_snat_ip_in_ep_file(host, ep_file, manifest_dir, snat_ips):
    if not snat_ips:
        return
    ep = get_ep_file_content(host, ep_file, manifest_dir)
    assert snat_ip_exists_in_ep(ep, snat_ips) is True, (
        'snat-ip - %s not found in EP file - %s' % (snat_ips, ep_file))


def check_service_id_and_name_exists_in_svc_file(svc_file_content,
                                                 service_id, service_name):
    service_id_matched = svc_file_content['uuid'] == service_id
    service_name_exists = 'name' in svc_file_content['attributes']
    service_name_matched = (svc_file_content['attributes']['name'] ==
                            service_name)
    return service_id_matched and service_name_exists and service_name_matched


def check_snat_id_in_ep_file(host, ep_file, manifest_dir, snat_ids):
    if not snat_ids:
        return
    ep = get_ep_file_content(host, ep_file, manifest_dir)
    assert snat_id_exists(ep, snat_ids) is True, (
        'snat-uuid - %s not found in EP file - %s' % (snat_ids, ep_file))


def get_snat_file_content(hostname, manifest_dir, snat_file):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    local_snat_file = '%s/%s' % (manifest_dir, snat_file)
    server.get(SNAT_FILE % snat_file, local_snat_file)
    with open(local_snat_file, 'r') as e:
        sf = json.load(e)
        LOG.info('******** SNAT file - %s - . Dump - %s '
                 '********' % (snat_file, pformat(sf)))
    return sf


def check_snat_ip_in_snat_file(hostname, snat_file, manifest_dir, snat_ips):
    sf = get_snat_file_content(hostname, manifest_dir, snat_file)
    assert snat_ip_exists(sf, snat_ips) is True, (
        'snat-ip - %s not found in snat_file - %s' % (snat_ips, snat_file))


@log_validation(name='SNAT localinfo validation')
def validate_localinfo(uid, hostname, snat_policy_name, snat_ips):
    pod_id_exists_in_localinfo(uid, hostname)
    snat_ips_exists_in_localinfo(hostname, snat_policy_name, snat_ips)


def validate_snat_ip_allocation(snat_allocation):
    kapi = KubeAPI()
    snat_ip_node_assoc = dict()  # {'I.P.' : [node-1, node-2]}
    snat_node_ip_assoc = dict()  # {'node-1': ('I.P.', 'UUID)}
    for snat_ip, node_info in snat_allocation.items():
        node_list = list()
        for info in node_info:
            if 'nodename' in info:
                node_list.append(info['nodename'])
        snat_ip_node_assoc[snat_ip] = node_list
    snat_global_info = kapi.get_detail(
        'snatglobalinfo', 'snatglobalinfo', namespace=CRD_NAMESPACE)
    global_infos = snat_global_info['spec']['globalInfos']
    for ip, node_list in snat_ip_node_assoc.items():
        count = 0
        for node in node_list:
            ip_and_uuid = list()
            for info in global_infos.get(node, []):
                ip_and_uuid.append((ip, info['snatIpUid']))
                if info['snatIp'] == ip:
                    count += 1

            snat_node_ip_assoc[node] = ip_and_uuid

        if count != len(node_list):
            raise Exception("Some nodes not listed in snatglobalinfo")
    return snat_node_ip_assoc


@log_validation(name='Endpoint file validation')
def validate_pod_ep_file(uid, hostname, manifest_dir, snat_ips=None,
                         snat_ids=None):
    wait_for_resource_convergence('endpoint')
    ep_file = get_ep_file_name_if_exists(hostname, uid)
    check_snat_ip_in_ep_file(hostname, ep_file, manifest_dir, snat_ips)
    check_snat_id_in_ep_file(hostname, ep_file, manifest_dir, snat_ids)


@log_validation(name='SNAT file validation')
def validate_snat_file_on_host_for_snat_ips(hostname, snat_ip_info,
                                            manifest_dir, snat_ips):
    for _, _id in snat_ip_info.items():
        snat_file = get_snat_file_name_if_exists(hostname, _id)
        check_snat_ip_in_snat_file(hostname, snat_file, manifest_dir, snat_ips)
        validate_port_range_overlap_in_snat_file(snat_file, manifest_dir)


def validate_port_range_overlap_in_snat_file(snat_file, manifest_dir):
    local_snat_file = '%s/%s' % (manifest_dir, snat_file)
    with open(local_snat_file, 'r') as snat_f:
        sf = json.load(snat_f)
    _check_port_range(sf, local_snat_file)


def _check_port_range(sf, snat_file):
    for ports in sf['port-range']:
        for remote_ports_info in sf.get('remote', []):
            for remote_ports in remote_ports_info['port-range']:
                if (remote_ports['start'] <= ports['start'] <= remote_ports[
                        'end']):
                    raise Exception("Port range overlap in SNAT file - %s" %
                                    snat_file)
                if (remote_ports['start'] <= ports['end'] <= remote_ports[
                        'end']):
                    raise Exception("Port range overlap in SNAT file - %s" %
                                    snat_file)


def capture_packet(interface, filter_ip, manifest_dir, dest_file,
                   short_delay=False):
    if not PCE:
        return
    pcap_file = manifest_dir + '/{}'.format(dest_file)
    cmd = 'tcpdump -nnei %s src %s or dst %s -w %s' % (
        interface, filter_ip, filter_ip, pcap_file)
    run_tcpdump_on_server(cmd, dest_file)
    # REVISIT(VK): Based on trials. May be going further we can remove ,
    # once this runs on different setup and we have baseline for datapath setup
    time.sleep(5) if short_delay else time.sleep(45)
    # kill_tcpdump()


def run_tcpdump_on_server(cmd, dest_file):
    if not REMOTE_ROUTER:
        subprocess.Popen([cmd], shell=True)
    else:
        try:
            capture_pkt_on_remote_server(cmd, dest_file)
        except Exception as e:
            LOG.error('Packet capture on remote server failed. cmd - %s  '
                      % cmd)
            raise
    LOG.info('........ Started pkt capture ........')


def capture_pkt_on_remote_server(cmd, dst_file):
    server = SRV_UTILS.get_external_router()
    scr_cmd = _reprocess_cmd(cmd, dst_file)
    server.run(scr_cmd)


def copy_pcap_file_from_remote_machine(file_name, local_dst):
    server = SRV_UTILS.get_external_router()
    try:
        server.get(src='/tmp/{}'.format(file_name),
                   dest='{}/{}'.format(local_dst, file_name))
    except Exception as e:
        LOG.error('Failed to copy - %s from external router. '
                  % '/tmp/{}'.format(file_name))
        raise


def copy_captured_dump_file(dest_file, manifest_dir):
    if REMOTE_ROUTER and PCE:
        LOG.info('........ Copying - %s file from external router to - %s '
                 '........', dest_file, manifest_dir)
        copy_pcap_file_from_remote_machine(dest_file, manifest_dir)
        LOG.info('........ Copying of - %s file completed ........', dest_file)


def _reprocess_cmd(cmd, dest_file):
    new_cmd = cmd.split()
    new_cmd[new_cmd.index('-w') + 1] = '/tmp/{}'.format(dest_file)
    new_cmd = ' '.join(new_cmd)
    return "sudo screen -S tcpdump-scr -dm " + new_cmd


def kill_tcpdump():
    if not PCE:
        return
    try:
        if REMOTE_ROUTER:
            kill_remote_tcpdump()
        else:
            kill_local_tcpdump()
    except Exception:
        pass


def kill_remote_tcpdump():
    server = SRV_UTILS.get_external_router()
    cmd = "for screen in $(screen -ls | grep tcpdump-scr);" \
          "do screen -S $screen -X quit; done"
    server.run(cmd)


def kill_local_tcpdump():
    res = os.system("pkill tcpdump")
    time.sleep(2)
    if res != 0:
        print('Failed to kill tcpdump')
        sys.exit(1)


@retry(no_of_retry=1 if not test_tuneup.get('retries') else test_tuneup[
    'retries'])
def generate_traffic(pod, external_ip, port, namespace='default',
                     ignore_retry=False):
    kapi = KubeAPI()
    # REVISIT(VK) - Implemented based on feedback to address issues/7
    kapi.kexec(
        pod,
        "for i in `seq 20 5 60`; do wget http://{}:{} -T $i -O "
        "/dev/null && "
        "break; done".format(external_ip, port),
        interpreter='sh -c',
        namespace=namespace)


def generate_traffic_and_capture_packet(pod, snat_ip, external_ip, port,
                                        external_interface, manifest_dir,
                                        dest_file, external_ip_pool_index,
                                        namespace='default'):
    # VK: Observed few case where this doesn't behaves deterministically
    # threads = [
    #     threading.Thread(target=capture_packet, args=(external_interface,
    #                      snat_ip, manifest_dir, dest_file), daemon=True),
    #     threading.Thread(target=generate_traffic, args=(pod, external_ip,
    #                      port), daemon=True)
    #     ]
    #
    # [t.start() for t in threads]
    #
    # [t.join(timeout=25) for t in threads]

    capture_packet(external_interface, snat_ip, manifest_dir, dest_file,
                   external_ip_pool_index > 0)
    generate_traffic(pod, external_ip, port, namespace)
    kill_tcpdump()
    copy_captured_dump_file(dest_file, manifest_dir)


def generate_traffic_from_pod(pod, snat_ip, external_ip, external_interface,
                              server_port, manifest_dir, dest_file,
                              external_ip_pool_index=0, namespace='default'):
    """
    Generates traffic from the given pod.

    :param pod: Pod name
    :param snat_ip: SNAT IP
    :param external_ip: IP to which pod will make connection
    :param external_interface: Interface on which Tcpdump will run
    :param server_port: Port on which server will listen
    :param manifest_dir:
    :param dest_file: Packet capture file name
    :param external_ip_pool_index: (Optional)
    :param namespace: Namespace to which pod belongs
    """
    launch_simple_server(server_port)
    generate_traffic_and_capture_packet(
        pod, snat_ip, external_ip, server_port, external_interface,
        manifest_dir, dest_file, external_ip_pool_index, namespace)
    kill_server()


def snat_ip_exists_as_source_in_pkt_dump(snat_ip, manifest_dir, dest_file):
    pcap_file = manifest_dir + '/{}'.format(dest_file)
    try:
        extraction = pcapkit.extract(fin=pcap_file, nofile=True)
        src_ip = str(extraction.frame[0][pcapkit.IP].src)
    except Exception as e:
        LOG.error("Failed to load packet capture file {} . Server "
                  "might not have received any packet.".format(pcap_file))
        return False
    return snat_ip == src_ip


def update_snat_policy_ip(policy_file, manifest_dir='/tmp', ip=None):
    with open(policy_file, 'r') as pf:
        policy = yaml.load(pf, Loader=yaml.SafeLoader)
    if ip and isinstance(ip, list):
        policy['spec']['snatIp'] = ip
    dst = get_dst_for_updated_manifest(manifest_dir, policy_file)
    copy_updated_yaml(policy, dst)
    return dst


def update_snat_policy_label(policy_file, labels, manifest_dir='/tmp'):
    with open(policy_file, 'r') as pf:
        policy = yaml.load(pf, Loader=yaml.SafeLoader)
    if isinstance(labels, dict):
        policy['spec']['selector']['labels'] = labels
    dst = get_dst_for_updated_manifest(manifest_dir, policy_file)
    copy_updated_yaml(policy, dst)
    return dst


def update_cm_ports_per_node(cm, ports_per_node):
    cm['data']['ports-per-node'] = ports_per_node
    tmp_dir = get_temp_dir()
    updated_manifest = tmp_dir + '/updated-snat-operator-config.yaml'
    copy_updated_yaml(cm, updated_manifest)
    return updated_manifest

def update_cm_ports_info(cm, ports_per_node='', start='', end=''):
    if ports_per_node:
        cm['data']['ports-per-node'] = ports_per_node
    if start:
        cm['data']['start'] = start
    if end:
        cm['data']['end'] = end
    tmp_dir = get_temp_dir()
    updated_manifest = tmp_dir + '/updated-snat-operator-config.yaml'
    copy_updated_yaml(cm, updated_manifest)
    return updated_manifest


def update_ds_image_name(ds, image_name=''):
    if image_name:
        ds['spec']['template']['spec']['containers'][0]['image'] = image_name
    tmp_dir = get_temp_dir()
    updated_manifest = tmp_dir + '/updated-host-agent-daemonset.yaml'
    copy_updated_yaml(ds, updated_manifest)
    return updated_manifest


@log_validation(name='Traffic validation')
def validate_traffic(manifest_dir, pod_name, snat_ip, namespace='default',
                     verify_multiple_targets=False):
    """
    Validate traffic. Generates traffic from pod, capture packet and
    validate captured packets.

    :param manifest_dir:
    :param pod_name: Name of the pod
    :param snat_ip: SNAT IP used in SNAT policy
    :param namespace: Namespace to which Pod belongs
    :param verify_multiple_targets: Pod generates traffic to multiple
    targets specified in input/cfg.py
    """
    if verify_multiple_targets:
        for ip_pool_index, external_ip in enumerate(EXTERNAL_IP_POOL):
            _verify_external_connectivity(
                manifest_dir, pod_name, snat_ip, external_ip, ip_pool_index,
                namespace, halt_when_fail=False)
    else:
        _verify_external_connectivity(
            manifest_dir, pod_name, snat_ip, EXTERNAL_ROUTER_IP,
            namespace=namespace)


@log_validation(name='Traffic validation')
def validate_traffic_for_given_destination(manifest_dir, pod_name, snat_ip,
                                           dest_ips, namespace='default'):
    for index, dest_ip in enumerate(dest_ips):
        _verify_external_connectivity(
            manifest_dir, pod_name, snat_ip, dest_ip, index,
            namespace=namespace, halt_when_fail=False)


def _verify_external_connectivity(manifest_dir, pod_name, snat_ip,
                                  external_ip, ip_pool_index=0,
                                  namespace='default',
                                  halt_when_fail=True):
    dest_file = get_pcap_file_name()
    generate_traffic_from_pod(pod_name, snat_ip, external_ip,
                              EXTERNAL_ROUTER_INTERFACE,
                              EXTERNAL_LISTENING_PORT,
                              manifest_dir,
                              dest_file,
                              ip_pool_index,
                              namespace)
    validate_snat_ip_in_pkt_dump(dest_file, external_ip, halt_when_fail,
                                 manifest_dir, pod_name, snat_ip)


def validate_snat_ip_in_pkt_dump(dest_file, external_ip, halt_when_fail,
                                 manifest_dir, pod_name, snat_ip):
    if not PCE:
        return
    if halt_when_fail:
        assert snat_ip_exists_as_source_in_pkt_dump(
            snat_ip, manifest_dir, dest_file) is True, (
                'Pod - %s cannot reach IP - %s' % (pod_name, external_ip))
    else:
        snat_ip_exists_as_source_in_pkt_dump(
            snat_ip, manifest_dir, dest_file)


def verify_snatlocalinfo_cleared_after_delete(policy_name, hostname):
    kapi = KubeAPI()
    localinfo = kapi.get_detail(
        'snatlocalinfo', name=hostname, namespace=CRD_NAMESPACE)
    for _, v in localinfo['spec'].get('localInfos', {}).items():
        if v['snatPolicyName'] == policy_name:
            return False
    return True


def verify_globalinfo_cleared_after_delete(svc_ip):
    globalinfo = get_detail('SnatGlobalInfo', 'snatglobalinfo',
                            namespace=CRD_NAMESPACE)
    for _, info in globalinfo['spec'].get('globalInfos', {}).items():
        for ginfo in info:
            if ginfo['snatIp'] == svc_ip:
                return False
    return True


def verify_null_mac_file_on_nodes():
    servers = SRV_UTILS.get_k8_cluster_objects()
    for server, _ in servers.items():
        null_mac_file_exists_on_host(server)
    LOG.info('........ null-mac ep file present on all nodes ........')


def null_mac_file_exists_on_host(hostname):
    server = SRV_UTILS.get_server_object_by_name(hostname)
    try:
        server.search_file_in_directory(EP_FILE_PATH, NULL_MAC_FILE_SEARCH_STR)
    except UnexpectedExit as e:
        LOG.error('null-mac ep file not found on host - %s . Exited with '
                  'code - %s' % (hostname, e.result.exited))
        raise

def restart_pods(selectors, namespace):
    """Restart the pods with provided selectors and namespace
    param selectors : List of selector in k: v format
    param namespace : namespace
    """
    kapi = KubeAPI()
    label_selector = ",".join(["%s=%s" % (k, v) for k, v in selectors.items()])
    kwargs = {"labels": label_selector}
    pods = kapi.get_detail("pod", namespace=namespace, **kwargs)
    LOG.info("........ Restarting Pods with labels %s ........" % label_selector)
    for pod in pods["items"]:
        LOG.info("........ Deleting pod %s ........" % pod["metadata"]["name"])
        kapi.delete_object(
            "pod", pod["metadata"]["name"], namespace=pod["metadata"]["namespace"]
        )
    check_pod_status(None, labels=label_selector, namespace=namespace)

def restart_controller(namespace=KUBE_SYSTEM):
    kapi = KubeAPI()
    kwargs = {'labels': 'name=aci-containers-controller'}
    pods = kapi.get_detail('pod', namespace=namespace, **kwargs)
    LOG.info("........ Restarting ACI Container Controller ........")
    for pod in pods['items']:
        kapi.delete_object('pod', pod['metadata']['name'],
                           namespace=pod['metadata']['namespace'])
    check_pod_status(None,
                     labels='name=aci-containers-controller',
                     namespace=namespace, timeout=240)

def restart_hostagent(namespace=KUBE_SYSTEM):
    kapi = KubeAPI()
    kwargs = {'labels': 'name=aci-containers-host'}
    pods = kapi.get_detail('pod', namespace=namespace, **kwargs)
    LOG.info("........ Restarting ACI Container Hostagent ........")
    for pod in pods['items']:
        kapi.delete_object('pod', pod['metadata']['name'],
                           namespace=pod['metadata']['namespace'])
    check_pod_status(None,
                     labels='name=aci-containers-host',
                     namespace=namespace, timeout=240)

def scale_deployment(deploy_name, no_of_replicas, namespace,
                     wait_until_scale=True,
                     timeout=120):
    kapi = KubeAPI()
    kapi.exec_cli_cmd("kubectl scale --replicas=%s deployment %s -n %s" %
                      (no_of_replicas, deploy_name, namespace))
    if wait_until_scale:
        check_available_deployment_replicas(
            deploy_name, namespace, no_of_replicas, timeout=timeout)


@log_update_cm
def update_snat_op_cfg_configmap(ports_per_node='', start='', end=''):
    kapi = KubeAPI()
    snat_cm = kapi.get_detail('configmap', name='snat-operator-config',
                              namespace=CRD_NAMESPACE)
    updated_manifest = update_cm_ports_info(
        snat_cm, ports_per_node=ports_per_node, start=start, end=end)
    label_str = ','.join('%s=%s' % (k, v) for k, v in snat_cm[
        'metadata']['labels'].items())
    label = {'label_str': label_str}
    # VK - Observed issue with labels of other resources
    kapi.apply(updated_manifest,
               label=label,
               manifest_dir=os.path.dirname(updated_manifest),
               namespace=CRD_NAMESPACE,
               skip_condition=True,
               delay=10)
    # VK: This is aligned with the test tuneup snatpolicy convergence timeout.
    wait_for_resource_convergence('snatpolicy')

def get_node_limit_for_snat_op_from_configmap():
    # snat-operator-config will not be there in case of chained mode
    if check_chained_mode():
        return 0
    kapi = KubeAPI()
    # Get snat-operator-config info from configmap
    snat_cm = kapi.get_detail('configmap', name='snat-operator-config',
                              namespace=CRD_NAMESPACE)
    ports_per_node = int(snat_cm['data']['ports-per-node'])
    start = int(snat_cm['data']['start'])
    end = int(snat_cm['data']['end'])
    max_node = int((end - start) / ports_per_node)
    LOG.info("Max node limit for SNAT %d", max_node)
    return max_node

def is_valid_cluster_for_snat_ds_test():
    is_valid = False
    max_snat_node = get_node_limit_for_snat_op_from_configmap()
    nodes = get_all_nodes_count_with_ready_state()
    LOG.info("Node Count %d Max Allowed Node %d" % (nodes, max_snat_node))
    is_valid = False if (nodes > max_snat_node) else True
    return is_valid

@log_check_conn_from_pod
def check_nw_connection_from_pod(pod_name, src_ip,
                                 targets, namespace='default'):
    """ Verify pod connectivity to the given targets
    :param pod_name: Pod from which traffic will be initiated
    :param src_ip: Will be used for validation.
    :param targets: List of tuples of dst ip and dst port
    :param namespace: Pod namespace
    """
    _validate_targets(targets)
    for dst_ip, dst_port in targets:
        generate_traffic(
            pod_name, external_ip=dst_ip, port=dst_port, namespace=namespace)


@log_check_conn_from_pod
def check_no_nw_connection_from_pod(pod_name, src_ip, targets,
                                    namespace='default',
                                    retry_on_error=False):
    """ Verify no connectivity from pod to the given targets
    :param pod_name: Pod from which traffic will be initiated
    :param src_ip: Will be used for validation.
    :param targets: List of tuples of dst ip and dst port
    :param namespace: Pod namespace
    :param retry_on_error: Override retry in generate_traffic method
    """
    _validate_targets(targets)
    for dst_ip, dst_port in targets:
        generate_traffic(
            pod_name, external_ip=dst_ip, port=dst_port, namespace=namespace,
            ignore_retry=not retry_on_error)


def _validate_targets(targets):
    assert isinstance(targets, list), (
        "Destination targets should be specified as [(ip, port), (ip, port)]")
    if not all([isinstance(t, tuple) and len(t) == 2 for t in targets]):
        raise Exception("Mismatch data types in target or (ip, port) is "
                        "missing - %s" % targets)


@log_check_conn_from_node
def verify_node_to_pod_reachability(server_name, pod_ip, server_ip=None,
                                    **kwargs):
    if not server_name and not server_ip:
        raise Exception('server_name and server_ip are None')
    if server_name:
        server = SRV_UTILS.get_server_object_by_name(server_name)
    elif server_ip:
        server = SRV_UTILS.get_server_object_by_ip(server_ip)
    cmd = "ping -c5 %s" % pod_ip
    server.run(cmd)


def validate_datapath(vm_ip, vm_username, vm_pass, svc_ip,
                      svc_port, inf_ip=None):
    """Verify datapath from given VM/ExtRouter node.

    :param vm_ip: The IP of VM/ExtRouter node.
    :param vm_username: Username of the VM.
    :param vm_pass: Password of the VM.
    :param svc_ip: IP of the service.
    :param svc_port : Port of the service.
    :param inf_ip: bind address for wget (optional).
    """
    LOG.info("Verifying reachability of service ip [%s]" % svc_ip)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(vm_ip, username=vm_username, password=vm_pass)
    if inf_ip:
        cmd = (('wget --bind-address="%s" http://%s:%s '
                '--connect-timeout=%s -t %s  &> /dev/null;'
                'if [[ "$?" != 0 ]]; then echo closed;'
                ' else echo open;fi') % (inf_ip, svc_ip,
                                         svc_port,
                                         WGET_CONNECTION_TIMEOUT,
                                         WGET_RETIRES))

    else:
        cmd = (('wget http://%s:%s --connect-timeout=%s '
                '-t %s  &> /dev/null;'
                'if [[ "$?" != 0 ]]; then echo closed;'
                ' else echo open;fi') % (svc_ip, svc_port,
                                         WGET_CONNECTION_TIMEOUT,
                                         WGET_RETIRES))

    LOG.info('Executing cmd [%s] from node [%s]' % (cmd, vm_ip))
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    exit_status = ssh_stdout.channel.recv_exit_status()
    if exit_status == 0:
        assert "open" in str(ssh_stdout.read()), (
            "Service IP[%s] is not reachable from node [%s]" % (svc_ip, vm_ip))
    else:
        ssh.close()
        assert False, ("Unable to execute command [%s] inside "
                       "Node[%s]" % (cmd, vm_ip))
    LOG.info("Service IP[%s] is reachable from node [%s]" % (svc_ip, vm_ip))
    ssh.close()


def run_command_remotely(vm_ip, vm_username, vm_pass, cmd, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if key_file:
        ssh.connect(vm_ip, username=vm_username, key_filename=key_file)
    else:
        ssh.connect(vm_ip, username=vm_username, password=vm_pass)
    LOG.info('Executing cmd [%s] from node [%s]' % (cmd, vm_ip))
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    exit_status = ssh_stdout.channel.recv_exit_status()
    if not exit_status == 0:
        ssh.close()
        assert False, ("Unable to execute command [%s] inside "
                       "Node[%s]" % (cmd, vm_ip))
    ssh.close()


def wait_for_resource_convergence(resource):
    if resource.lower() in test_tuneup.get('resources'):
        resource_timeout = resource.lower() + "_convergence_timeout"
        wait_time = 10 if resource_timeout not in test_tuneup else \
            test_tuneup[resource_timeout]
        LOG.info("Waiting for %s up to %s secs to converge ..." % (
            resource, wait_time))
        time.sleep(wait_time)
    else:
        wait_time = test_tuneup.get('default_wait_time', 10)
        LOG.info("Waiting for another %s seconds + + +" % wait_time)
        time.sleep(wait_time)


def get_dest_ips_from_config(count=1):
    external_ips = list()
    for index in range(count):
        ipaddress.ip_address(EXTERNAL_IP_POOL[index])
        external_ips.append(EXTERNAL_IP_POOL[index])
    return external_ips


def generate_random_string(length):
    """Returns random string of given length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def get_files_from_dir(dir):
    """Returns list of files from given path."""
    filepaths = [f.name for f in os.scandir(dir) if f.is_file()]
    return filepaths


def get_dir_from_dir(dir):
    """Returns list of directory from given path."""
    dirpaths = [f.name for f in os.scandir(dir) if f.is_dir()]
    return dirpaths


def check_pods_count(namespace, expected_count, labels=None):
    condition = Condition('check no of matching pods',
                          globals()['check_no_of_pods'],
                          namespace,
                          labels,
                          expected_count)
    wait_for_condition(condition, timeout=120, interval=10)


def check_no_of_pods(namespace='default', labels=None,
                     expected_no_of_pods=-1):
    kapi = KubeAPI()
    if expected_no_of_pods < 1:
        return True
    kwargs = {'namespace': namespace}
    if labels:
        kwargs['labels'] = ','.join(labels)
    pods = kapi.get_detail('pod', **kwargs)
    while len(pods['items']) != expected_no_of_pods:
        return False
    for pod in pods['items']:
        if "running" not in pod['status']['containerStatuses'][0]['state']:
            return False
    return True


def verify_ingress_route_status(name, namespace):
    route = get_detail('route', name, namespace)
    if route['status']['ingress']:
        if route['status']['ingress'][0]['conditions'][0]['status'] == \
                'True' and 'host' in route['status']['ingress'][0]:
            return True
        else:
            return False
    else:
        return False


# Run command on rtr or on test container based on run_on_router flag
def run_cmd(cmd, run_on_router):
    if run_on_router:
        cmd = 'sudo bash -c "%s"' % cmd
        res = SRV_UTILS.get_external_router().run(cmd)
        output = res
    else:
        res = subprocess.Popen([cmd], stdout=subprocess.PIPE,
                               shell=True)
        output, err = res.communicate(timeout=30)
        if res.returncode != 0:
            raise Exception(err)
        output = output.decode()
    LOG.debug(output)
    return output

# update /etc/hosts file
def update_host_file(update_str, op, run_on_router=False):
    file_name = "/etc/hosts"
    if op == 'add':
        # Add at the starting
        cmd = 'cp %s ./hosts.new; sed -i \'1i %s\' ./hosts.new;cp ./hosts.new %s' % (file_name, update_str, file_name)
    elif op == 'delete':
        cmd = 'cp %s ./hosts.new;sed -i \'/%s/d\' ./hosts.new;cp ./hosts.new %s' % (file_name, update_str, file_name)
    else:
        raise Exception("Invalid operation")
    LOG.debug("run_on_router: %r OP %s cmd : %s" %(run_on_router, op, cmd))
    run_cmd(cmd, run_on_router)


def get_podif_name(name, namespace):
    kapi = KubeAPI()
    pod_detail = kapi.get_detail('pod', name=name, namespace=namespace)
    node_ip = pod_detail['status']['hostIP']
    return '{}.{}.{}'.format(namespace, name, node_ip)

def get_podif_epg(name, namespace='kube-system'):
    kapi = KubeAPI()
    podif_detail = kapi.get_detail('podif', name=name, namespace=namespace)
    epg = podif_detail['status']['epg']
    epg_decon = epg.split("|")
    podif_epg = epg_decon[-1]
    return podif_epg

def get_podif_app_profile(name, namespace='kube-system'):
    kapi = KubeAPI()
    podif_detail = kapi.get_detail('podif', name=name, namespace=namespace)
    epg = podif_detail['status']['epg']
    epg_decon = epg.split("|")
    podif_ap = epg_decon[0]
    return podif_ap

def get_podif_mac(name, namespace='kube-system'):
    kapi = KubeAPI()
    podif_detail = kapi.get_detail('podif', name=name, namespace=namespace)
    podif_mac = podif_detail['status']['macaddr']
    return podif_mac.upper()


def validate_svc_file_on_host(hostname, service_uid, service_name,
                              manifest_dir):
    wait_for_resource_convergence('svc_file')
    assert check_svc_file_if_exists(hostname, service_uid) is True, (
            "service file for id - %s not found on host - %s" % (
                service_uid, hostname))
    svc_file = SVC_FILE % (service_uid + '.service')
    validate_service_attribs_in_service_file(
        hostname, svc_file, service_uid, service_name, manifest_dir)


def validate_service_attribs_in_service_file(host, service_file, service_id,
                                             service_name, manifest_dir):
    svc = get_svc_file_content(host, service_file, manifest_dir)
    assert check_service_id_and_name_exists_in_svc_file(
        svc, service_id, service_name) is True, (
            'service attributes - %s - %s not matched in svc file on host - %s'
            % (service_id, service_name, host))
    LOG.info("Service file validation for service - %s done successfully" %
             service_name)


def transform_mac(mac):
	m = mac.replace(":", "-")
	return m


def exec_cmd(cmd):
    if True:
        kapi = KubeAPI()
        try:
            exec_cli = kapi.exec_cli_cmd(cmd)
            print(exec_cli)
        except Exception as ex:
            LOG.error("Resource creation failed for the cmd with %s", ex)


def create_resource_from_template(resource, fixture):
    template = env.get_template(resource['template'])
    rend_template = template.render(input=resource)
    template_name = f"{resource['name']}.yaml"
    dump_template(template_name, rend_template)
    return create_resource(template_name, fixture)


def apply_resource_from_template(resource):
    template = env.get_template(resource['template'])
    rend_template = template.render(input=resource)
    template_name = f"{resource['name']}.yaml"
    dump_template(template_name, rend_template)
    return apply_resource(template_name)


def get_k8s_resource_count(resource):
    kapi = KubeAPI()
    kube_client = get_kube_client()
    resource_count = 0
    cmd = "%s get %s -A -o=jsonpath='{.items[*].metadata.name}'" % (kube_client, resource)
    output = kapi.exec_cli_cmd(cmd)
    if output == b"''":
        LOG.info("Unable to get object count for resource %s" % (resource))
    else:
        resource_count = len(output.split())
    return resource_count


def update_hpp_optimization_controller(cm_name, cm_ns, value=False):
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    controller_config = json.loads(config_map['data']['controller-config'])

    config_map['data']['controller-config'] = controller_config

    current_value = False

    if "hpp-optimization" in config_map['data']['controller-config']:
        current_value = controller_config['hpp-optimization']

    LOG.info("current hpp-optimization value in controller-config : %r" % current_value)
    if current_value != value:
        LOG.info("Updating hpp-optimization value in controller-config to : %r" % value)
        config_map['data']['controller-config']\
            ["hpp-optimization"] = value

        config_map['data']['controller-config'] = json.dumps(config_map['data']\
            ['controller-config'], indent=4, cls=DataEncoder)

        patch_params = {'update_str' : json.dumps(
                            [{"op": "add",
                                "path": "/data/controller-config",
                                "value": config_map['data']['controller-config']}]),
                        'type' : 'json'}

        kapi.patch('ConfigMap', name=cm_name, patch_params=patch_params,\
                namespace=cm_ns)

        restart_controller(namespace=cm_ns)


def update_hpp_optimization_hostagent(cm_name, cm_ns, value=False):
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    hostagent_config = json.loads(config_map['data']['host-agent-config'])

    config_map['data']['host-agent-config'] = hostagent_config

    current_value = False

    if "hpp-optimization" in config_map['data']['host-agent-config']:
        current_value = hostagent_config['hpp-optimization']

    LOG.info("current hpp-optimization value in host-agent-config : %r" % current_value)
    if current_value != value:
        LOG.info("Updating hpp-optimization value in host-agent-config to : %r" % value)
        config_map['data']['host-agent-config']\
            ["hpp-optimization"] = value

        config_map['data']['host-agent-config'] = json.dumps(config_map['data']\
            ['host-agent-config'], indent=4, cls=DataEncoder)

        patch_params = {'update_str' : json.dumps(
                            [{"op": "add",
                                "path": "/data/host-agent-config",
                                "value": config_map['data']['host-agent-config']}]),
                        'type' : 'json'}

        kapi.patch('ConfigMap', name=cm_name, patch_params=patch_params,\
                namespace=cm_ns)

        restart_hostagent(namespace=cm_ns)

def update_enable_hpp_direct_controller(cm_name, cm_ns, value=False):
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    controller_config = json.loads(config_map['data']['controller-config'])

    config_map['data']['controller-config'] = controller_config

    current_value = False

    if "enable-hpp-direct" in config_map['data']['controller-config']:
        current_value = controller_config['enable-hpp-direct']

    LOG.info("current enable-hpp-direct value in controller-config : %r" % current_value)
    if current_value != value:
        LOG.info("Updating enable-hpp-direct value in controller-config to : %r" % value)
        config_map['data']['controller-config']\
            ["enable-hpp-direct"] = value

        config_map['data']['controller-config'] = json.dumps(config_map['data']\
            ['controller-config'], indent=4, cls=DataEncoder)

        patch_params = {'update_str' : json.dumps(
                            [{"op": "add",
                                "path": "/data/controller-config",
                                "value": config_map['data']['controller-config']}]),
                        'type' : 'json'}

        kapi.patch('ConfigMap', name=cm_name, patch_params=patch_params,\
                namespace=cm_ns)

        restart_controller(namespace=cm_ns)


def update_enable_hpp_direct_hostagent(cm_name, cm_ns, value=False):
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    hostagent_config = json.loads(config_map['data']['host-agent-config'])
    opflexagent_config = json.loads(config_map['data']['opflex-agent-config'])

    config_map['data']['host-agent-config'] = hostagent_config
    config_map['data']['opflex-agent-config'] = opflexagent_config

    current_value = False

    if "enable-hpp-direct" in config_map['data']['host-agent-config']:
        current_value = hostagent_config['enable-hpp-direct']

    LOG.info("current enable-hpp-direct value in host-agent-config : %r" % current_value)
    if current_value != value:
        LOG.info("Updating enable-hpp-direct value in host-agent-config to : %r" % value)
        config_map['data']['host-agent-config']\
            ["enable-hpp-direct"] = value
        config_map['data']['opflex-agent-config']\
            ["opflex"]["enable-local-netpol"] = value

        config_map['data']['host-agent-config'] = json.dumps(config_map['data']\
            ['host-agent-config'], indent=4, cls=DataEncoder)
        config_map['data']['opflex-agent-config'] = json.dumps(config_map['data']\
            ['opflex-agent-config'], indent=4, cls=DataEncoder)

        patch_params = {'update_str' : json.dumps(
                            [{"op": "add",
                                "path": "/data/host-agent-config",
                                "value": config_map['data']['host-agent-config']},
                             {"op": "add",
                                "path": "/data/opflex-agent-config",
                                "value": config_map['data']['opflex-agent-config']}]),
                        'type' : 'json'}

        kapi.patch('ConfigMap', name=cm_name, patch_params=patch_params,\
                namespace=cm_ns)

        restart_hostagent(namespace=cm_ns)


def update_image_in_host_daemonset(daemonset_name, image_name):
    kapi = KubeAPI()
    try:
        daemonset_details = get_detail('daemonset',
                                name=daemonset_name,
                                namespace=CRD_NAMESPACE)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s DaemonSet does not exist", daemonset_name)
        assert False, ("Validating daemonset failed, Reason: %s" % e.message)

    updated_manifest = update_ds_image_name(
        daemonset_details, image_name=image_name)
    label_str = ','.join('%s=%s' % (k, v) for k, v in daemonset_details[
        'metadata']['labels'].items())
    label = {'label_str': label_str}
    kapi.apply(updated_manifest,
               label=label,
               manifest_dir=os.path.dirname(updated_manifest),
               namespace=CRD_NAMESPACE,
               skip_condition=True,
               delay=10)
    wait_for_resource_convergence(daemonset_details['kind'])
    restart_hostagent(namespace=CRD_NAMESPACE)


def show_cpu_memory_usage_difference(test_name):
    if COLLECT_PROFILING_DATA is False:
        return
    namespace = CRD_NAMESPACE
    pods = get_all_pods(namespace)

    cpu_memory_usage_diff_dict = {}
    try:
        for pod in pods['items']:
            pod_name = pod['metadata']['name']
            if "openvswitch" in pod_name:
                continue
            directory = "/tmp/%s/" % test_name  # e.g /tmp/test_stress
            cpu_memory_usage_diff_dict[pod_name] = {}
            for when in ["after-test-run", "before-test-run"]:
                fname = "%s-%s.txt" % (pod_name, when)
                top_cmd_txt_file_abspath = directory + fname
                cmd = "cat %s | grep 'aci-containers'" % top_cmd_txt_file_abspath
                cpu_memory_usage = subprocess.Popen(
                    [cmd], stdout=subprocess.PIPE, shell=True
                ).communicate()[0].decode("utf-8")

                # split by " " and remove " " from the returned list
                cpu_memory_usage = list(filter(None, cpu_memory_usage.split(" ")))
                cpu_usage = int(cpu_memory_usage[1][:-1])
                memory_usage = int(cpu_memory_usage[2][:-2])

                cpu_memory_usage_diff_dict[pod_name].update({
                    when: {
                        "cpu": cpu_usage,
                        "memory": memory_usage
                    }
                })

        print("ACI containers cpu/memory usage dict: %s" % json.dumps(cpu_memory_usage_diff_dict, indent=4))
        print("\n\n====== ACI Containers before and after test run cpu/memory usage difference ======\n")
        print("NAME                                        CPU(cores)  MEMORY(bytes)")
        for pod_name, value in cpu_memory_usage_diff_dict.items():
            cpu_diff = (cpu_memory_usage_diff_dict[pod_name]["after-test-run"]["cpu"] -
                        cpu_memory_usage_diff_dict[pod_name]["before-test-run"]["cpu"])
            memory_diff = (cpu_memory_usage_diff_dict[pod_name]["after-test-run"]["memory"] -
                           cpu_memory_usage_diff_dict[pod_name]["before-test-run"]["memory"])
            print("%s                     %sm        %sMi" % (pod_name, cpu_diff, memory_diff))
    except Exception as e:
        print("Exception %s in show_cpu_memory_usage_difference()" % e)


def collect_profiling_data(test_name, when):
    """
    Collect 'pprof profiling data' and 'kubectl top' command output of
    aci-containers-controller and aci-containers-host pods.

    :param test_name: test module name e.g "test_stress", "test_stress_2" etc
    :param when: when profiling data is collected "before-test-run" or "after-test-run".
    :return: None. Collected data is stored at /tmp/<test_name> location.
    """

    if COLLECT_PROFILING_DATA is False:
        return

    namespace = CRD_NAMESPACE
    pods = get_all_pods(namespace)
    for pod in pods['items']:
        pod_name = pod['metadata']['name']
        if "openvswitch" in pod_name:
            continue

        directory = "/tmp/%s/" % test_name  # e.g /tmp/test_stress
        os.makedirs(directory, exist_ok=True)

        pprof_file = "%s-%s.pprof" % (pod_name, when)  # e.g aci-containers-host-9ffbd-before-test-run.pprof
        pprof_file_abspath = directory + pprof_file
        # containers-host port 8090, containers-controller port 8091
        port = "8091" if "controller" in pod_name else "8090"
        pprof_kcmd = "kubectl exec %s -n %s -- curl http://localhost:%s/debug/pprof/heap > %s" % (
            pod_name, namespace, port, pprof_file_abspath)
        os.system(pprof_kcmd)

        top_cmd_txt_file = "%s-%s.txt" % (pod_name, when)  # e.g aci-containers-host-9ffbd-before-test-run.txt
        top_cmd_txt_file_abspath = directory + top_cmd_txt_file
        top_kcmd = "kubectl top pod  %s -n %s > %s" % (pod_name, namespace, top_cmd_txt_file_abspath)
        os.system(top_kcmd)


def check_for_svc_eps_ready(svc_name, svc_namespace):
    LOG.info("Checking Service %s endpoint status in ns %s" % (svc_name, svc_namespace))
    endpoint = get_detail('endpoints', name=svc_name, namespace=svc_namespace)
    endpointslice = get_detail('endpointslice', name=None, namespace=svc_namespace)
    if endpointslice['items'][0]['endpoints']:
        for eps in endpointslice['items'][0]['endpoints']:
            if endpoint['subsets'][0]['addresses'][0]['ip'] != eps['addresses'][0]:
                continue
            return eps['conditions']['ready']
    return False


def wait_for_svc_ep_ready(name, namespace):
    condition = Condition(
        'check for service endpointslice Ready condition', globals()[
            'check_for_svc_eps_ready'],
       name, namespace)
    wait_for_condition(condition, timeout=120, interval=10)


def update_config_and_restart_controller(config, namespace):
    kapi = KubeAPI()
    tmp_dir = get_temp_dir()
    updated_manifest = tmp_dir + '/updated-cm-config.yaml'
    copy_updated_yaml(config, updated_manifest)
    label_str = ','.join('%s=%s' % (k, v) for k, v in config[
        'metadata']['labels'].items())
    label = {'label_str': label_str}
    kapi.apply(updated_manifest,
               label=label,
               manifest_dir=os.path.dirname(updated_manifest),
               namespace=namespace,
               skip_condition=True,
               delay=10)
    restart_controller(namespace=namespace)


def get_hpp_optimization_controller_and_hostagent_current_value(cm_name, cm_ns):
    controller_current_value = False
    hostagent_current_value = False
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    controller_config = json.loads(config_map['data']['controller-config'])
    hostagent_config = json.loads(config_map['data']['host-agent-config'])

    config_map['data']['controller-config'] = controller_config
    config_map['data']['host-agent-config'] = hostagent_config

    if "hpp-optimization" in config_map['data']['controller-config']:
         controller_current_value = controller_config['hpp-optimization']
    if "hpp-optimization" in config_map['data']['host-agent-config']:
        hostagent_current_value = hostagent_config['hpp-optimization']

    LOG.info("current hpp-optimization value in  controller-config : %r host-agent-config : %r" %
            (controller_current_value, hostagent_current_value))
    return controller_current_value, hostagent_current_value

def get_enable_hpp_direct_controller_and_hostagent_current_value(cm_name, cm_ns):
    controller_current_value = False
    hostagent_current_value = False
    kapi = KubeAPI()
    try:
        config_map = get_detail('ConfigMap',
                                name=cm_name,
                                namespace=cm_ns)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", cm_name)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    controller_config = json.loads(config_map['data']['controller-config'])
    hostagent_config = json.loads(config_map['data']['host-agent-config'])

    config_map['data']['controller-config'] = controller_config
    config_map['data']['host-agent-config'] = hostagent_config

    if "enable-hpp-direct" in config_map['data']['controller-config']:
         controller_current_value = controller_config['enable-hpp-direct']
    if "enable-hpp-direct" in config_map['data']['host-agent-config']:
        hostagent_current_value = hostagent_config['enable-hpp-direct']

    LOG.info("current enable-hpp-direct value in  controller-config : %r host-agent-config : %r" %
            (controller_current_value, hostagent_current_value))
    return controller_current_value, hostagent_current_value


def update_hpp_optimization(cm_name, cm_ns, controller_value=False, hostagent_value=False):
    LOG.info("Updating hpp-optimization controller-config : %r host-agent-config : %r" %
            (controller_value, hostagent_value))
    update_hpp_optimization_controller(cm_name, cm_ns, controller_value)
    update_hpp_optimization_hostagent(cm_name, cm_ns, hostagent_value)

def update_hpp_direct(cm_name, cm_ns, controller_value=False, hostagent_value=False):
    LOG.info("Updating enable-hpp-direct controller-config : %r host-agent-config : %r" %
            (controller_value, hostagent_value))
    update_enable_hpp_direct_controller(cm_name, cm_ns, controller_value)
    update_enable_hpp_direct_hostagent(cm_name, cm_ns, hostagent_value)


def wait_for_pod_running(selectors, replicas=1, namespace='default'):
    """Wait for pod running status for provided selectors and namespace
    param selectors : List of selector in k: v format
    param replicas : expected no. of pods
    param namespace : namespace
    """
    kapi = KubeAPI()
    label_selector = ",".join(["%s=%s" % (k, v) for k, v in selectors.items()])
    kwargs = {"labels": label_selector}
    LOG.info("........ Checking Pods with labels %s ns %s........" % (label_selector, namespace))
    pods = kapi.get_detail("pod", namespace=namespace, **kwargs)
    for pod in pods["items"]:
        replicas = replicas - 1
        LOG.info("........ pod %s ........" % pod["metadata"]["name"])
    assert replicas == 0, ("Some pods are not created")
    check_pod_status(None, labels=label_selector, namespace=namespace)


def wait_for_resources_deleted(selectors, resource_type='pod', namespace='default', timeout=120):
    """
    Wait for all resources of a specific type to be deleted based on provided selectors and namespace.
    
    :param selectors: List of selector in k: v format
    :param resource_type: Type of the Kubernetes resource (e.g., 'pod', 'service', 'deployment')
    :param namespace: Kubernetes namespace
    :param timeout: Maximum time to wait for resources to be deleted, in seconds
    """
    label_selector = ",".join(["%s=%s" % (k, v) for k, v in selectors.items()])
    LOG.info("........ Checking %s with labels %s in namespace %s ........" % (resource_type, label_selector, namespace))
    
    condition = Condition(
        'check resources deletion', globals()['are_resources_deleted'],
        resource_type, label_selector, namespace
    )
    wait_for_condition(condition, timeout=timeout, interval=10)

def are_resources_deleted(resource_type, labels, namespace):
    """
    Check if all resources of a specific type with the given labels are deleted.
    
    :param resource_type: Type of the Kubernetes resource (e.g., 'pod', 'service', 'deployment')
    :param labels: Label selector string
    :param namespace: Kubernetes namespace
    :return: True if all resources are deleted, False otherwise
    """
    kapi = KubeAPI()
    kwargs = {"labels": labels}
    resources = kapi.get_detail(resource_type, namespace=namespace, **kwargs)
    return len(resources["items"]) == 0


def get_worker_node_count():
    workers = get_worker_nodes_hostname_with_ready_state()
    count = len(workers)
    assert count != 0, ("No Worker node found with Running State")
    LOG.info("%d Worker nodes found with Running State" % count)
    return count


def reboot_node(node_name):
    server_obj = SRV_UTILS.get_server_object_by_name(node_name)

    # execute reboot command
    cmd = 'reboot'
    server_obj.run(cmd, su=True)


def poll_node_ready_after_reboot(node_name, prev_node_boot_id):
    kapi = KubeAPI()
    interval_seconds = 10

    start_time = time.time()
    timeout = getattr(cfg, 'NODE_READY_AFTER_REBOOT_TIMEOUT', 600)
    while time.time() - start_time < timeout:
        node = kapi.get_detail('node', name=node_name)
        curr_node_boot_id = node.get('status', {}).get('nodeInfo', {}).get('bootID', '')

        # Check if node is rebooted.
        if curr_node_boot_id != prev_node_boot_id:
            # Check if node is ready
            if is_node_ready(node):
                total_time = time.time() - start_time
                LOG.info("Node %s is ready. Time taken to be ready after reboot is %d seconds",
                         node_name, total_time)
                return total_time

        # If node is not ready, sleep for interval_seconds and retry.
        LOG.info("Node %s is not ready after reboot. Retrying in %s seconds...",
                 node_name, interval_seconds)
        time.sleep(interval_seconds)

    assert False, ("Timeout while waiting for node: %s to be ready", node_name)


def get_input_for_namespace(name):
    return {
        'name': name,
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }


def create_pod(pod_input, base_fixture):
    pod_manifest = lib_helper.get_pod_manifest(
        'alp_cust.jsonnet', pod_input['name'], pod_input.get('namespace'),
        pod_input.get('labels'), pod_input.get('image'), pod_input.get('node'))
    pod = create_resource(pod_manifest, base_fixture)
    label_str = ''
    for k, v in pod['add_label'].items():
        label_str += k + '=' + v + ','
    pod['label_str'] = label_str[:-1]
    return pod


def get_input_for_svc_and_deployment(deploy, svc, selectors, node_name = None, **kwargs):
    default_replica_count = lib_helper.get_cluster_node_count()
    default_labels = {'key': 'test', 'val': 'test_dp'}

    deployment = {
        'name': deploy['name'],
        'namespace': deploy.get('namespace', 'default'),
        'labels': deploy.get('labels', default_labels),
        'template': 'nginx_deployment.yaml',
        'kind': 'deployment',
        'replicas': deploy.get('replicas', default_replica_count)
    }

    svc = {
        'name': svc['name'],
        'namespace': svc.get('namespace', 'default'),
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'lb_type': kwargs.get('lb_type', 'LoadBalancer')
    }

    if selectors:
        deployment['selector'] = selectors
        svc['selector'] = selectors

    if node_name:
        deployment['node'] = node_name

    return deployment, svc


def check_ew_traffic(base_fixture, gen_template_name, src_pod):
    """
    Verify ping working from source pod to all other pods lunched in all nodes
    through daemonset.
    """

    daemonset = {
        'name': 'test-nginx-ds',
        'template': 'nginx_ds.yaml',
        'kind': 'daemonset',
        'selector': {'name': 'test-ew-traffic'},
    }

    for resource in [daemonset]:
        template = env.get_template(resource['template'])
        rend_template = template.render(input=resource, pod=resource)
        temp_name = gen_template_name(resource['name'])
        lib_helper.dump_template(temp_name, rend_template)
        create_resource(temp_name, base_fixture)

    new_pods = lib_helper.get_pods_by_labels(daemonset['selector'])

    for _pod in new_pods:
        lib_helper.check_ping_from_pod(
            src_pod['metadata']['name'],
            src_pod['metadata']['namespace'],
            _pod[1])


def check_snat_for_pod(base_fixture, gen_template_name, pod, manifest_dir):
    uid = pod['metadata']['uid']
    hostname = pod['spec']['nodeName']

    snat = {
        'name': 'snat-test-for-pod',
        'template': 'snat_policy.yaml',
        'snat-ip': '151.20.1.50',
        'labels': pod['metadata']['labels']
    }

    template = env.get_template(snat['template'])
    rend_temp = template.render(input=snat)
    temp_name = gen_template_name(snat['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    policy = create_resource(temp_name, base_fixture)

    snat_policy = get_detail('SnatPolicy', name=policy['name'], namespace=policy['namespace'])
    snat_ips = get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = get_snat_ids_from_policy(snat_policy)

    verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    validate_pod_ep_file(uid, hostname, manifest_dir, snat_ids=snat_ids)
    snat_ip_info = get_snat_ids(hostname, snat_ips)
    validate_snat_file_on_host_for_snat_ips(hostname, snat_ip_info, policy['manifest_dir'], snat_ips)
    validate_traffic(manifest_dir, pod['metadata']['name'], snat_ips[0])


def is_node_ready(node):
    for condition in node['status']['conditions']:
        if condition.get('type') == "Ready" and condition.get('status') == "True":
            return True
    return False

def verify_current_nodes():
    """This function will check if all the nodes are in ready state"""
    kapi = KubeAPI()
    nodes = kapi.get_detail('nodes')
    for node in nodes['items']:
        for condition in node['status']['conditions']:
            if condition['type'] == 'Ready' and condition['status'] == 'False':
                assert False, (f"Node {node['metadata']['name']} not is ready state")
    return len(nodes['items'])

def create_install_cluster_snat(base_fixture):
    """
    This function creates the cluster snatpolicy required before node scale up
    """

    if check_snat_already_exists():
        return

    manifest_path = '{}/sample_snat_policy.yaml'.format(DATA_DIR)
    with open(manifest_path, 'r') as file:
        manifest = yaml.safe_load(file)

    if 'spec' in manifest and 'selector' in manifest['spec']:
        del manifest['spec']['selector']
    manifest['metadata']['name'] = 'installerclusterdefault'
    manifest['spec']['snatIp'] = ['151.10.1.20/32']

    dump_template('installerclusterdefault', str(manifest))
    create_resource('installerclusterdefault', base_fixture)

def check_snat_already_exists():
    kapi = KubeAPI()
    snat_policy = kapi.get_detail('snatpolicy')
    for snat in snat_policy['items']:
        if snat['metadata']['name'] == 'installerclusterdefault':
            return True
    return False

def get_ext_network():
    hostname = get_ext_router_node_hostname()
    server = SRV_UTILS.get_server_object_by_name(hostname)
    ext_network = server.run("cat ~/openupi/install-config.yaml | grep externalNetwork")
    external_network = ext_network.stdout.split(':')[-1].strip()
    return external_network

def attach_fip():
    """ This function assigns a floating ip to the new worker node"""
    external_network = get_ext_network()
    cmd = ("scripts.attach_fip_to_nodes", "--overcloudrc", "/acc-pytests/tests/input/overcloudrc", "--ext_network", external_network)
    run_script_in_container(*cmd)

def poll_for_new_node_entry(nodes_count):
    """ This function polls for the new node to come up and returns the name of node"""
    kapi = KubeAPI()
    interval = 5
    start_time = time.time()
    while time.time() - start_time < NODE_WAIT_TIMEOUT:
        nodes = kapi.get_detail("nodes")
        LOG.info('Wait for the new node to come up . . .')
        if len(nodes['items']) == (nodes_count + 1):
            for node in nodes['items']:
                for condition in node['status']['conditions']:
                    if condition['type'] == 'Ready' and condition['status'] == 'False':
                        return node['metadata']['name']
        time.sleep(interval)
    return False

def wait_till_node_ready(node_name, timeout=NODE_WAIT_TIMEOUT):
    """
    Function to wait for the node to come in ready state
    """
    kapi = KubeAPI()
    interval = 10
    start_time = time.time()
    failed_count = 0
    LOG.info('Waiting for the node %s to come in ready state max time %d. . .' % (node_name, timeout))
    while time.time() - start_time < timeout:
        node = kapi.get_detail('nodes', node_name)
        LOG.debug('[%d]Waiting for the node %s to come in ready state. . .' % (failed_count, node_name))
        for condition in node['status']['conditions']:
            if condition['type'] == 'Ready' and condition['status'] == 'True':
                time_diff = int(time.time() - start_time) if failed_count > 0 else 0
                LOG.info('Node name %s moved to Ready state in %s Sec. . .' % (node_name, time_diff))
                return True, time_diff
        failed_count = failed_count + 1
        time.sleep(interval)

    return False, -1


def run_script_in_container(cmd, *args):
    try:
        subprocess.run(["python", "-m", cmd, *args], check=True)
    except Exception as e:
        assert False, (f"Error running script in container: {e}")


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

def is_acc_provision_operator_excluded():
    """ Get acc_provision_operator exclude flag value.
    """
    value = False
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    if apic_provision.get("acc_provision_operator"):
        value = apic_provision["acc_provision_operator"].get("exclude", False)
    return value

def get_aci_containers_host_version(pod_name='aci-containers-host',
                                    container_name='aci-containers-host',
                                    namespace=lib_helper.get_aci_namespace()):
    """ Get host agent version """
    version = "None"
    resource_details = get_detail('daemonset', pod_name, namespace)
    container_details = resource_details['spec']['template']['spec']['containers']
    for container in container_details:
        if container['name'] == container_name:
            image_version =  container['image'].split(":")[1]
            ver = image_version.split('.', 4)
            version = '.'.join(ver[0:-1])
    LOG.info("Host opflex agent version : %s", version)
    return version

def check_nncp_status(nncp_name):
    nncp_details = get_detail('nncp', nncp_name)
    if nncp_details:
        nncp_status = nncp_details['status']['conditions'][0]['reason']
        if nncp_status == 'SuccessfullyConfigured':
            return True
    return False


def wait_for_nncp_successfully_configured(nncp_name):
    condition = Condition(
        'check for NNCP status SuccessfullyConfigured condition', globals()[
            'check_nncp_status'],
       nncp_name)
    wait_for_condition(condition, timeout=120, interval=10)


def add_nadvlanmapping(namespace, new_config):
    kapi = KubeAPI()
    nadvlanmap = kapi.get_detail('nadvlanmap', namespace=namespace)
    for key in new_config.keys():
        nadvlanmap['items'][0]['spec'][
            'nadVlanMapping'][key] = new_config[key]

    tmp_dir = get_temp_dir()
    updated_manifest = tmp_dir + '/updated-nadvlanmap.yaml'
    copy_updated_yaml(nadvlanmap, updated_manifest)
    kapi.apply(updated_manifest,
               manifest_dir=os.path.dirname(updated_manifest),
               namespace=namespace,
               skip_condition=True,
               delay=10)


def remove_nadvlanmapping(namespace, nadmapping_name):
    kapi = KubeAPI()
    nadvlanmap = kapi.get_detail('nadvlanmap', namespace=namespace)

    if nadvlanmap['items']:
        del nadvlanmap['items'][0]['spec'][
                    'nadVlanMapping'][nadmapping_name]

        tmp_dir = get_temp_dir()
        updated_manifest = tmp_dir + '/updated-nadvlanmap.yaml'
        copy_updated_yaml(nadvlanmap, updated_manifest)
        kapi.apply(updated_manifest,
                manifest_dir=os.path.dirname(updated_manifest),
                namespace=namespace,
                skip_condition=True,
                delay=10)


def get_config_from_configmap(config='host-agent-config'):
    """
    Returns info from ConfigMap based on Provided config
    :param config: Name of the Config. Possible value host-agent-config(Default),
                   controller-config, opflex-agent-config
    """
    kapi = KubeAPI()
    try:
        config_map = kapi.get_detail('ConfigMap',
                                    name=CONFIGMAP_NAME,
                                    namespace=CONFIGMAP_NAMESPACE)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist on Namespace %s" %
                      (CONFIGMAP_NAME, CONFIGMAP_NAMESPACE))
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    config = json.loads(config_map['data'][config])
    return config


def get_info_from_configmap(config='host-agent-config', field="node-subnet"):
    """
    Returns info from ConfigMap based on Provided config and field
    :param config: Name of the Config. Possible value host-agent-config(Default),
                   controller-config, opflex-agent-config
    :param field: Name of the field to get the info
    """
    config = get_config_from_configmap(config)
    return config.get(field, '')


def compress_subnets(subnets):
    """ Compress IPv6 subnets
    :param subnets: List of subnet to compress
    """
    comp_subnets = []
    for subnet in subnets:
        comp_subnet = ipaddress.ip_interface(subnet)
        comp_subnets.append(str(comp_subnet))
    return comp_subnets


def is_openstack():
    flavor = get_info_from_configmap(field="flavor")
    if 'openstack' in flavor:
        return True
    return False


def get_node_subnets_from_cm():
    """ Returns node-subnet from ConfigMap """
    node_subnets = get_info_from_configmap(field="node-subnet")
    return compress_subnets(node_subnets)


def get_pod_subnets_from_cm():
    """ Returns pod-subnet from ConfigMap """
    pod_subnets = get_info_from_configmap(field="pod-subnet")
    return compress_subnets(pod_subnets)

def get_per_node_max_pod(nodename):
    kapi = KubeAPI()
    nodes = kapi.get_detail('nodes')
    max_pods = 0
    for node in nodes['items']:
        max_pods = int(node['status']['allocatable']['pods'])
        LOG.info("Node %s Max pods : %d" % (node['metadata']['name'], max_pods))
        if nodename is None:
            break
        if node['metadata']['name'] == nodename:
            break
    return max_pods

def get_pod_running_on_node(nodename):
    kapi = KubeAPI()
    pods = kapi.exec_cli_cmd(f"kubectl get po -A -owide --field-selector spec.nodeName={nodename}").decode('utf-8').split('\n')
    return len(pods)
