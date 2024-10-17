from acc_pyutils.api import KubeAPI
from acc_pyutils import logger

NAMESPACE = "aci-containers-system"
CONTAINER = "opflex-agent"

LOG = logger.get_logger(__name__)

def test_check_unresolved_platform_config():
    kapi = KubeAPI()
    pods = kapi.get_detail('pod', namespace=NAMESPACE, l="name=aci-containers-host")
    pod_names = [pod['metadata']['name'] for pod in pods['items'] if 'aci-containers-host-' in pod['metadata']['name']]
    for pod in pod_names:
        LOG.info('Checking unresolved platform config . . .')
        result = kapi.kexec(pod, 'hostname', namespace=NAMESPACE, container=CONTAINER, interpreter="gbp_inspect -rfpq DmtreeRoot -u")
        data = result.decode('utf-8', 'ignore')
        assert 'Platform' not in data, (data)
