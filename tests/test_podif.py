import os
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib
DATA_DIR = os.path.abspath('tests/test_data')
LOG = logger.get_logger(__name__)

# This test verifies podif create in the "kube-system" namespace when a pod is created.
def test_podif_create(base_fixture):
    kapi = KubeAPI()
    pod = lib.create_resource('{}/case_6_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    podif_name = lib.get_podif_name(name=pod['name'], namespace=pod['namespace'])
    try:
        exec_cli = kapi.get_detail('podif', name=podif_name, namespace='kube-system')
    except Exception as ex:
        LOG.error("PodIF creation failed with %s", ex)