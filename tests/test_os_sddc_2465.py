import os

from acc_pyutils.utils import execute
from tests import lib

DATA_DIR = os.path.abspath('tests/test_data')


def test_pod_scaling(base_fixture):
    project = lib.create_resource('{}/sddc_2465_prj.yaml'.format(DATA_DIR),
                                  base_fixture)
    deployment = lib.create_resource(
        '{}/sddc_2465_deploy.yaml'.format(DATA_DIR), base_fixture)
    svc = lib.create_resource('{}/sddc_2465_svc.yaml'.format(DATA_DIR),
                              base_fixture)
    svc_detail = lib.get_detail('service', svc['name'], project['name'])
    assert svc_detail['spec']['clusterIP'] is not None
    route = lib.create_resource('{}/sddc_2465_route.yaml'.format(DATA_DIR),
                                base_fixture)
    route = lib.get_detail('route', route['name'], namespace=project['name'])
    # Check status of exposed route
    assert route['status']['ingress'][0]['conditions'][0]['status'] == "True"
    # REVISIT(VK): Check how to verify connectivity, as this is not
    # reachable from router ?
    # url = 'http://' + route['spec']['host']
    scale_up = 'oc scale deployments docker-demo -n ci-sddc2465-pod-scaling ' \
               '--replicas=5'
    execute(scale_up.split(" "))
    lib.check_available_deployment_replicas(deployment['name'], project[
        'name'], expected_replica_nos=5)
