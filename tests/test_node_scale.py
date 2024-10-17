import os
import time
import yaml
import pytest
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib, lib_helper, validate_snat_apic_resource
from tests.template_utils import env
from tests.test_datapath import _get_input_for_namespace
from tests.input.cfg import APIC_VALIDATION
from tests.input import cfg
from tests.server_utils import ServerUtils


SRV_UTILS = ServerUtils()
LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
RESOURCE_MACHINESET = 'machineset'
NAMESPACE = 'openshift-machine-api'
POD_NAMESPACE = 'node-scale'
DEPLOYMENT_NAME = 'node-scale-test'
POD_COUNT = 30
NETWORK_ERROR_TIMEOUT = 300
DELETE_TIMEOUT = 420

@pytest.mark.skipif(not lib.is_openstack(), reason='openstack related')
@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.usefixtures("clean_gen_templates")
def test_node_scale(base_fixture, gen_template_name):
    """
    Testcase to verify the bring of of new node.
    This test includes:
    1. Creation of a new node
    2. Creating a pod in the newly created node
    3. Testing pod-svc traffic
    4. Testing ping between pods
    5. Testing east-west traffice
    6. Verify traffic using snat
    """

    """ This function will check if the current nodes are in ready state before trigerring the test."""
    nodes_count = lib.verify_current_nodes()
    LOG.info('All current nodes in ready state. Exectuing test. . . ')

    """This function creates the cluster snatpolicy required before node scale up"""
    lib.create_install_cluster_snat(base_fixture)

    kapi = KubeAPI()
    new_node_name = ""
    pods = None
    script_commands = []
    machine_set = kapi.get_detail(RESOURCE_MACHINESET, namespace=NAMESPACE)
    resource_name = machine_set['items'][0]['metadata']['name']
    replicas = machine_set['items'][0]['status']['replicas'] + 1

    LOG.info('Upgrading the number of nodes to %s . . .' % replicas)
    try:
        kapi.exec_cli_cmd('oc scale %s -n %s %s --replicas=%s' %(RESOURCE_MACHINESET, NAMESPACE, resource_name, replicas))

    except Exception as e:
        assert False, "Error upgrading the nodes: {}".format(str(e))

    LOG.info('Wait for the new node to come up . . .')

    try:

        """Function to wait till an entry of new code is created"""
        new_node_name = lib.poll_for_new_node_entry(nodes_count)
        assert new_node_name, ("New node didn't come up in time")

        LOG.info('Wait for the new node to come in ready state . . .')
        """ Function to wait while the newly created node comes in ready state"""
        is_ready, _ = lib.wait_till_node_ready(new_node_name)
        assert is_ready, ("Node creation failed")

        """This configures the new worker node"""
        lib.attach_fip()
        password = getattr(cfg, 'PODMAN_PASSWORD', 'None')
        script_commands = [
            ("scripts.update_node_info", "--key", "/acc-pytests/tests/input/id_rsa", "--overcloudrc", "/acc-pytests/tests/input/overcloudrc"),
            ("scripts.node_info_validate",),
            ("scripts.nodes_docker_login", "-f", "openshift", "-p", password, "-n", new_node_name),
            ("scripts.image_pull","-f", "openshift", "-p", password, "-n", new_node_name),
        ]
        for cmd in script_commands:
            lib.run_script_in_container(*cmd)

        """ create a new namespace where we will create our resources"""
        create_namespace(base_fixture, gen_template_name)

        """ Creation of 30 pods in the newly created node"""
        pods = create_pods(new_node_name, base_fixture)

        """ Test the traffic between the pod and service """
        check_pod_svc_traffic(base_fixture, gen_template_name, new_node_name)

        """This function check the traffice between the pods created on the new node"""
        check_traffic_between_pods(pods)

        """ This function verifies the east-west traffic"""
        check_ew_traffic(base_fixture, gen_template_name, pods[0])

        """ This function verifies the traffic using snat """
        check_snat_for_pod(base_fixture, gen_template_name, new_node_name)

    finally:
        if pods:
            """ Delete the 30 pods deployment"""
            kapi.delete_object('deployment', DEPLOYMENT_NAME, namespace=POD_NAMESPACE)

        """This function creates the cluster snatpolicy required before node scale down"""
        lib.create_install_cluster_snat(base_fixture)

        """ Removing the new created node """
        LOG.info('Scaling down machineset . . .')
        kapi.exec_cli_cmd('oc scale %s -n %s %s --replicas=%s' %(RESOURCE_MACHINESET, NAMESPACE, resource_name, machine_set['items'][0]['status']['replicas']))
        try:
            assert wait_for_node_delete(machine_set['items'][0]['status']['replicas']), ("Node deletion failed")

        finally:
            """Update the node_info.yaml file after node deletion"""
            if script_commands:
                for cmd in script_commands[:2]:
                    lib.run_script_in_container(*cmd)


def check_for_network_error():
    LOG.info('Checking for any network error after the pods are launched. . .')
    kapi = KubeAPI()
    interval = 5
    start_time = time.time()
    try:
        while time.time() - start_time < NETWORK_ERROR_TIMEOUT:
            nw_error = kapi.exec_cli_cmd(f'oc get events -n %s' %POD_NAMESPACE)
            nw_error_str = nw_error.decode('utf-8')
            if "Gave up waiting for network" not in nw_error_str:
                LOG.info('No network error . . .')
                return True
            time.sleep(interval)
        return False
    except Exception as e:
        assert False, ("Error while checking for network errors: {}".format(str(e)))

def create_pods(new_node_name, base_fixture):
    kapi = KubeAPI()
    deployment_manifest_path = '{}/node_scale_apline_deployment.yaml'.format(DATA_DIR)
    with open(deployment_manifest_path, 'r') as file:
        deployment_manifest = yaml.safe_load(file)

    deployment_manifest['spec']['template']['spec']['nodeName'] = new_node_name
    deployment_manifest['metadata']['name'] = DEPLOYMENT_NAME
    deployment_manifest['spec']['replicas'] = POD_COUNT
    lib_helper.dump_template(deployment_manifest['metadata']['name'], str(deployment_manifest))
    lib.create_resource(deployment_manifest['metadata']['name'], base_fixture)
    LOG.info('Pods deployed in the newly created node %s . . .' % new_node_name)

    pods_detail = kapi.get_detail('pod', namespace=POD_NAMESPACE)
    pods = [pod for pod in pods_detail['items'] if DEPLOYMENT_NAME in pod['metadata']['name']]

    assert (check_for_network_error()), ("Network error during pod creation")
    return pods

def create_namespace(base_fixture, gen_template_name):
    ns = _get_input_for_namespace(POD_NAMESPACE)
    template = env.get_template(ns['template'])
    rend_temp = template.render(input=ns)
    temp_name = gen_template_name(ns['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)

def wait_for_node_delete(nodes):
    """
    This function waits for the node to delete
    """
    kapi = KubeAPI()
    interval = 5
    start_time = time.time()
    while  time.time() - start_time < DELETE_TIMEOUT:
        try:
            machines = kapi.get_detail('machine', namespace=NAMESPACE)
            LOG.info('Wait for node to delete . . .')
            if len(machines['items']) == nodes:
                return True
        except Exception as e:
            LOG.error("Error while waiting for node scale down: {}".format(str(e)))
        time.sleep(interval)
    LOG.error("Node did not scale down in time")
    return False

def check_pod_svc_traffic(base_fixture, gen_template_name, new_node_name):
    """
    This function creates a deployment and service to test the traffic
    """
    ns = _get_input_for_namespace('su-val')
    selector = {'test': 'su-dp-validation'}
    deploy_in = {'name': 'su-nginx-deploy', 'namespace': ns['name']}
    svc_in = {'name': 'su-nginx-svc', 'namespace': ns['name']}
    deployment, svc = lib.get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector, new_node_name)

    LOG.info('Creating namespace, deployment and service to test the traffic. . .')
    for rsc in [ns, deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    LOG.info('Verifying traffic. . . ')
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace',
                                                             'default'))
    """Deleting the resources"""
    kapi = KubeAPI()
    kapi.delete_object('deployment', deployment['name'], namespace=ns['name'])
    kapi.delete_object('svc', svc['name'], namespace=ns['name'])
    kapi.delete_object('ns', ns['name'])

def check_traffic_between_pods(pods):
    LOG.info('Verifying ping between pods. . . ')
    p1_name = pods[0]['metadata']['name']
    p2_name = pods[1]['metadata']['name']
    LOG.info("Testing ping traffic between pods %s %s"% (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tip = lib_helper.get_pod_ip(dst_pod, POD_NAMESPACE)
        lib_helper.check_ping_from_pod(p_name, POD_NAMESPACE, tip, target='pod')

def check_ew_traffic(base_fixture, gen_template_name, pod):
    LOG.info('Verifying east-west traffic. . . ')
    daemonset = {
        'name': 'test-nginx-ds',
        'template': 'nginx_ds.yaml',
        'kind': 'daemonset',
        'selector': {'name': 'test-ew-traffic'}
    }
    for rsrc in [daemonset]:
        template = env.get_template(rsrc['template'])
        rend_template = template.render(input=rsrc, pod=rsrc)
        temp_name = gen_template_name(rsrc['name'])
        lib_helper.dump_template(temp_name, rend_template)
        lib.create_resource(temp_name, base_fixture)
    new_pods = lib_helper.get_pods_by_labels(daemonset['selector'])
    for _pod in new_pods:
        lib_helper.check_ping_from_pod(
            pod['metadata']['name'],
            pod['metadata']['namespace'],
            _pod[1])

    """Deleting resource"""
    kapi = KubeAPI()
    kapi.delete_object('daemonset', daemonset['name'])

def check_snat_for_pod(base_fixture, gen_template_name, new_node_name):
    LOG.info('Deleting installer cluster snat policy before running snat test. . . ')
    kapi = KubeAPI()
    kapi.exec_cli_cmd('oc delete snatpolicy installerclusterdefault')

    LOG.info('Verifying snat for pod traffic. . . ')

    pod = None
    policy = None

    pod_manifest_path = '{}/busybox.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['spec']['nodeName'] = new_node_name
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    try:
        policy = lib.create_resource('{}/sample_snat_policy.yaml'.format(DATA_DIR), base_fixture)
        snat_policy = lib.get_detail('SnatPolicy', name=policy['name'], namespace=policy['namespace'])
    
        snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
        snat_ids = lib.get_snat_ids_from_policy(snat_policy)
        lib.verify_null_mac_file_on_nodes()

        if APIC_VALIDATION:
            validate_snat_apic_resource.test_apic(snat_ips)
        lib.validate_pod_ep_file(uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(hostname, snat_ip_info, policy['manifest_dir'], snat_ips)
        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0])

    finally:
        """Deleting resources"""
        if pod and pod.get('name'):
            kapi.delete_object('pod', pod['name'])
        if policy and policy.get('name'):
            kapi.delete_object('snatpolicy', policy['name'])
