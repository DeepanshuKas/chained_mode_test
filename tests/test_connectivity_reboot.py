import pytest
import os
import yaml
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib
import tests.scale_test_helper as scale_helper

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')

@pytest.mark.usefixtures("clean_gen_templates")
def test_connectivity_reboot(base_fixture, gen_template_name):
    ns = scale_helper.SVC_TEST_NS
    kapi = KubeAPI()
    summary = list()
    resources = {}

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

    summary.append({'Test Node': node_name})
    LOG.info("Creating resources")
    try:
        scale_helper.create_datapath_resources_in_parallel(base_fixture, ['reboot-test'], resources, nodename=node_name, max_pod=True)
        scale_helper.check_datapath_connectivity(base_fixture, ['reboot-test'], resources, nodename=node_name, svc_curl=True)
        summary.append({'Pods_Count': resources[ns]['deployment']['replicas']})
        # reboot the node
        lib.reboot_node(node_name)
        time = lib.poll_node_ready_after_reboot(node_name, node_boot_id)
        summary.append({'Node Ready time': time})
        #Check aci pods are running and ready
        is_running, time_taken = lib.poll_for_aci_pods(node_name)
        assert is_running, ("ACI pods did not come in ready state after %s Sec. Timed out", time_taken)
        summary.append({'ACI pods Ready time': time_taken})
        #Check all pods are in running state after reboot
        is_running, time_taken = lib.check_all_pods_running_and_ready(
            resources[ns]['deployment']['replicas'], resources[ns]['namespace']['name'],
            resources[ns]['deployment']['labels'])
        assert is_running, ("All pods not in ready true state")
        summary.append({'Pods_Ready_Time': time_taken})
        LOG.info("Verifying pod-svc connectivity after reboot")
        scale_helper.check_datapath_connectivity(base_fixture, ['reboot-test'], resources, nodename=node_name, max_pod=True)
        scale_helper.delete_datapath_resources(base_fixture, resources)
        LOG.info("Recreate resources and verify connectivity")
        scale_helper.create_resources_and_check_datapath_connectivity(base_fixture, ['reboot-test'], nodename=node_name, max_pod=True)
    finally:
        scale_helper.delete_datapath_resources(base_fixture, resources)
        dump_summary(summary)

def dump_summary(summary):
    LOG.info("=======Node Reboot Test Stats ========")
    for stat in summary:
        for k, v in stat.items():
            LOG.info("%s : %s %s" % (k, str(v), "Sec" if "time" in k else ""))
    LOG.info("======================================")
