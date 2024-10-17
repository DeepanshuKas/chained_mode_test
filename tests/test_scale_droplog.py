import os
import pytest

from acc_pyutils.acc_cfg import get_kube_client
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib
from tests import lib_helper
from tests.template_utils import env

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
POD_COUNT = 100


@pytest.mark.usefixtures("clean_gen_templates")
def test_scale_droplog(base_fixture, gen_template_name):
    """Test scale droplog.

    This test performs below steps.
    1)launch pods on same node.
    2)Check status of all the pods.
    3)Once all the pods are Running, check the drop logs of all the pods.

    """
    kapi = KubeAPI()
    node = lib.get_worker_nodes_hostname()[0]
    scale_droplog = _get_input_for_namespace('scale-droplog-test')
    template = env.get_template(scale_droplog['template'])
    rend_temp = template.render(input=scale_droplog)
    temp_name = gen_template_name(scale_droplog['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture)
    kube_client = get_kube_client()
    inventory_path = DATA_DIR + "/inventory.yaml"
    if kube_client == "oc":
        template_name = "os-curl-pod.yaml.j2"
    else:
        template_name = "k8s-curl-pod.yaml.j2"
    yaml_path = DATA_DIR + "/curl-test.yaml"
    cmd = ("ansible-playbook -i %s  %s -e  pod_count=%s -e ns_name=%s "
           " -e node_name=%s -e t_name=%s" % (inventory_path, yaml_path,
                                              POD_COUNT, scale_droplog['name'],
                                              node, template_name))
    LOG.info("Executing cmd:%s" % cmd)
    os.system(cmd)
    lib.check_pods_count("scale-droplog-test", POD_COUNT + 1)
    kwargs = {'namespace': "scale-droplog-test"}
    pods = kapi.get_detail('pod', **kwargs)
    for pod in pods['items']:
        pod_details = kapi.describe('pod', pod['metadata']['name'],
                                    namespace="scale-droplog-test")
        assert ("Int-POL_TABLE MISS(Policy Drop)" not in pod_details.decode())


def _get_input_for_namespace(name):
    return {
        'name': name,
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }
