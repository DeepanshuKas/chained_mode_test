import pytest

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib, lib_helper
from tests.template_utils import env


LOG = logger.get_logger(__name__)


@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.usefixtures("clean_gen_templates")
def test_connectivity_after_node_reboot(gen_template_name, base_fixture):
    """
    Reboot any worker node.
    Verify communications after reboot.
    """
    kapi = KubeAPI()

    # Get any worker node ip.
    nodes = kapi.get_detail('nodes')
    assert len(nodes['items']) != 0, ("no nodes present in cluster")

    for node in nodes['items']:
        # Check if worker node.
        if "node-role.kubernetes.io/worker" in node['metadata']['labels']:
            # Check if node is ready
            if lib.is_node_ready(node):
                # Taking the first ready worker node and rebooting it
                node_name = node['metadata']['name']
                node_boot_id = node.get('status', {}).get('nodeInfo', []).get('bootID', '')
                break

    # Run reboot command remotely on the worker node
    lib.reboot_node(node_name)

    # Poll for node to be ready
    lib.poll_node_ready_after_reboot(node_name, node_boot_id)

    # Verify communications intact after reboot.
    # Doing all resource creation on the rebooted node.

    # Create pod
    pod_name = 'test-reboot-pod'
    pod_input = {
        'name': pod_name,
        'labels': {'test': 'reboot-ping-pod'},
        'image': 'noiro-quay.cisco.com/noiro/alpine-utils:latest',
        'node': node_name
    }
    pod_info = lib.create_pod(pod_input, base_fixture)
    pod = kapi.get_detail(
        'pod', **{'labels': pod_info['label_str']})['items'][0]

    # Create service
    ns_name = 'reboot-test'
    ns = lib.get_input_for_namespace(ns_name)
    selector = {'test': 'reboot-test-selector'}
    deploy_input = {'name': 'reboot-nginx-deploy', 'namespace': ns_name, 'replicas': 1}
    svc_input = {'name': 'reboot-nginx-svc', 'namespace': ns_name}
    deployment, svc = lib.get_input_for_svc_and_deployment(
        deploy_input, svc_input, selector, node_name)

    LOG.info("Creating namespace, deployment and service. . .")
    for resource in [ns, deployment, svc]:
        template = env.get_template(resource['template'])
        rend_temp = template.render(input=resource)
        temp_name = gen_template_name(resource['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    LOG.info("Verifying pod to service traffic. . .")
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic-validation', ns_name)

    LOG.info("Verifying east west traffic. . .")
    lib.check_ew_traffic(base_fixture, gen_template_name, pod)

    LOG.info("Verifying snat for pod. . .")
    lib.check_snat_for_pod(base_fixture, gen_template_name, pod, pod_info['manifest_dir'])
