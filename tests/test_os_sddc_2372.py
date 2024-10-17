import os

from acc_pyutils.api import KubeAPI
from acc_pyutils.utils import execute
from tests import lib

DATA_DIR = os.path.abspath('tests/test_data')


def test_os_web_service(base_fixture):
    kapi = KubeAPI()
    project = lib.create_resource(
        '{}/sddc_2372_prj.yaml'.format(DATA_DIR), base_fixture)
    # (VK) API for new-app cannot be realized. So, we need to execute from cli
    # directly.
    new_app = "oc new-app jboss-webserver31-tomcat8-openshift:1.4~https" \
              "://github.com/linus78/myjavaapp.git -n %s" % project['name']
    execute(new_app.split(" "))
    lib.check_service_ip('myjavaapp', namespace=project['name'])
    svc = kapi.get_detail('service', 'myjavaapp', namespace=project['name'])
    assert svc['spec']['clusterIP'] is not None
    lib.create_resource('{}/sddc_2372_route.yaml'.format(DATA_DIR),
                        base_fixture)
    route = kapi.get_detail('route', 'myjavaapp', namespace=project['name'])
    # Check status of exposed route
    assert route['status']['ingress'][0]['conditions'][0]['status'] == "True"
