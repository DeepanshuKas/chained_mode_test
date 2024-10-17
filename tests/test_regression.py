import pytest

from tests import lib, lib_helper
from tests.template_utils import env


def get_pod_input(name, namespace=None):
    if not namespace:
        namespace = 'default'
    return {
        'name': name,
        'namespace': namespace
    }


@pytest.mark.usefixtures("clean_gen_templates")
def test_connect_node_pod(base_fixture, gen_template_name):
    template = env.get_template('alpine.yaml')
    pod_input = get_pod_input('tcpfn-alp')
    rend_temp = template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)
    pod = lib.get_detail(
        'pod', pod_input['name'], pod_input.get('namespace', 'default'))
    pod_ip, host_ip = pod['status']['podIP'], pod['status']['hostIP']
    node_name = lib_helper.get_node_name_by_ip(host_ip)
    lib.verify_node_to_pod_reachability(node_name, pod_ip, target='pod')
    lib_helper.check_ping_from_pod(
        pod['metadata']['name'], pod['metadata']['namespace'], host_ip,
        target='node')


# @pytest.mark.commontest
@pytest.mark.skip(reason="Test needs extra privileges")
@pytest.mark.usefixtures("clean_gen_templates")
def test_connect_hostpod(base_fixture, gen_template_name):
    # Pod manifest details for host_network_pod and non_host_network_pod
    host_pod_input = get_pod_input('host-pod')
    host_pod_input['host_network'] = 'true'
    pod_input = get_pod_input('dest-pod')

    # Creating the pods
    _create_pod(base_fixture, gen_template_name,
                'alpine.yaml', host_pod_input)
    _create_pod(base_fixture, gen_template_name,
                'alpine.yaml', pod_input)

    # Get host_pod ip
    host_pod = lib.get_detail(
        'pod', host_pod_input['name'],
        host_pod_input.get('namespace', 'default'))
    host_pod_ip, _ = host_pod['status']['podIP'], host_pod['status']['hostIP']

    # Get pod_ip
    pod = lib.get_detail(
        'pod', pod_input['name'], pod_input.get('namespace', 'default'))
    pod_ip, pod_node_ip = pod['status']['podIP'], pod['status']['hostIP']

    # Checking ping between host_pod(pod with host network)
    # And another pod(pod without host network)
    # host_pod is considered as node as it having same host network
    # This is to verify reachability between node and pod
    lib_helper.check_ping_from_pod(
        host_pod['metadata']['name'], host_pod['metadata']['namespace'],
        pod_ip,
        target='pod')

    # Verify reachability between pod and node
    lib_helper.check_ping_from_pod(
        pod['metadata']['name'], pod['metadata']['namespace'], pod_node_ip,
        target='node')


@pytest.mark.commontest
@pytest.mark.usefixtures("clean_gen_templates")
def test_non_root_pod(base_fixture, gen_template_name):
    # Note(VK): Use different user than 65534 once kubernetes 1.17.0
    # is released.
    template = env.get_template('nonrootpod.yaml')
    pod_input = {'name': 'tnrp-alp', 'label': 'nonroot-test'}
    rend_temp = template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)


def _create_pod(base_fixture, gen_template_name,
                template_name, pod_input):
    """
    Creates the pod corresponding to pod_input and
    template_name

    Args:
    template_name(str): template names for pod manifest
    pod_input(dict): attributes for pod manifest template
    """
    template = env.get_template(template_name)
    rend_temp = template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)
