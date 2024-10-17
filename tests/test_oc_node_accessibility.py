import pytest

from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib

CLIENT = get_kube_client()
LOG = logger.get_logger(__name__)


@pytest.mark.skipif(CLIENT != "oc", reason="this is openshift "
                    "specific node accessbility test")
def test_oc_node_accessability():
    """Verify openshift nodes accessability."""
    kapi = KubeAPI()
    master_node_list = lib.get_master_nodes_hostname()
    worker_node_list = lib.get_worker_nodes_hostname()
    node_list = master_node_list + worker_node_list
    for node in node_list:
        cmd = '%s debug node/%s' % (CLIENT, node)
        LOG.info("Verifying accessability of node[%s]" % node)
        try:
            kapi.exec_cli_cmd(cmd)
            LOG.info("Node[%s] is accessible" % node)
        except Exception as e:
            assert False, ("Node[%s] is not accessible, Reason %s" % (node, e))
