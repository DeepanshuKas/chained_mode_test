import os

from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from tests import lib, lib_helper
from tests.template_utils import env

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
NGINX_TEMPLATE = env.get_template('nginx_non_root_pod.yaml')
NGINX_SVC_TEMPLATE = env.get_template('nginx_service.yaml')


def test_node_local_service(base_fixture, gen_template_name):
    workers = lib.get_worker_nodes_hostname()
    if len(workers) < 1:
        LOG.info("No worker node found, hence kipping the test run.")
        return

    pod1_input = {'name': 'nginx-tcls-1', 'node': workers[0], 'labels': {
        'app': 'nginx-tnls'
    }}
    pod = create_nginx_pod(base_fixture, gen_template_name, pod1_input,
                           NGINX_TEMPLATE)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    # service
    svc_input = {'name': 'nginx-tcls-svc', 'selector': {'app': 'nginx-tnls'},
                 'labels': {'test': 'test_node_local_service'},
                 'lb_type': 'LoadBalancer',
                 'topology_keys': ["kubernetes.io/hostname"]}
    svc = create_nginx_service(base_fixture, gen_template_name, svc_input,
                               NGINX_SVC_TEMPLATE)
    svc_uid, _, _, _ = lib.get_service_details(svc['name'])

    lib.validate_svc_file_on_host(hostname, svc_uid, svc['name'],
                                  svc['manifest_dir'])

    # traffic tester pod
    pod_input = {'name': 'tnls-tester', 'image': 'noiro-quay.cisco.com/noiro/alp-curl',
                 'node': workers[0]}
    test_pod = create_pod(pod_input, base_fixture)

    check_traffic_from_pod_to_svc(test_pod, svc)

    # create another pod in different node
    if len(workers) < 2:
        LOG.info("Only one worker found, hence skipping rest of the test run.")
        return
    pod2_input = {'name': 'nginx-tcls-2', 'node': workers[1], 'labels': {
        'app': 'nginx-tnls'
    }}
    pod2 = create_nginx_pod(base_fixture, gen_template_name, pod2_input,
                            NGINX_TEMPLATE)
    pod2_uid, _, pod2_hostname = lib.get_pod_details(name=pod2['name'])
    lib.validate_svc_file_on_host(pod2_hostname, svc_uid, svc['name'],
                                  svc['manifest_dir'])
    check_traffic_from_pod_to_svc(test_pod, svc)


def test_topology_aware_svc_on_zone(base_fixture, gen_template_name):
    kapi = KubeAPI()
    workers = lib.get_worker_nodes_hostname()
    masters = lib.get_master_nodes_hostname()
    for node in workers + masters:
        kapi.exec_cli_cmd("kubectl label nodes %s "
                          "topology.kubernetes.io/zone=zone1 "
                          "--overwrite=True" % node)
    pod1_input = {'name': 'nginx-tcls-zone-1', 'node': workers[0], 'labels': {
        'app': 'nginx-tnls'
    }}
    pod = create_nginx_pod(base_fixture, gen_template_name, pod1_input,
                           NGINX_TEMPLATE)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    # service
    svc_input = {'name': 'nginx-tcls-zone-svc',
                 'selector': {'app': 'nginx-tnls'},
                 'labels': {'test': 'test_topology_aware_svc_on_zone'},
                 'lb_type': 'LoadBalancer',
                 'topology_keys': ["kubernetes.io/hostname",
                                   "topology.kubernetes.io/zone"]}
    svc = create_nginx_service(base_fixture, gen_template_name, svc_input,
                               NGINX_SVC_TEMPLATE)
    svc_uid, _, _, _ = lib.get_service_details(svc['name'])

    for node in workers:
        lib.validate_svc_file_on_host(node, svc_uid, svc['name'],
                                      svc['manifest_dir'])

    # traffic tester pod
    pod_input = {'name': 'ttasoz-tester', 'image': 'noiro-quay.cisco.com/noiro/alp-curl'}
    test_pod = create_pod(pod_input, base_fixture)

    check_traffic_from_pod_to_svc(test_pod, svc)

    for node in workers + masters:
        if hostname != node:
            kapi.exec_cli_cmd("kubectl label nodes %s "
                              "topology.kubernetes.io/zone-" % node)

    lib.validate_svc_file_on_host(hostname, svc_uid, svc['name'],
                                  svc['manifest_dir'])

    for node in workers + masters:
        if hostname != node:
            assert lib.check_svc_file_if_exists(node, svc_uid) is False

    check_traffic_from_pod_to_svc(test_pod, svc)


def create_nginx_pod(base_fixture, gen_template_name, pod_input, pod_template):
    rend_temp = pod_template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    return lib.create_resource(temp_name, base_fixture)


def create_nginx_service(base_fixture, gen_template_name, svc_input,
                         svc_template):
    rend_temp = svc_template.render(input=svc_input)
    temp_name = gen_template_name(svc_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    return lib.create_resource(temp_name, base_fixture)


def create_pod(pod_input, base_fixture):
    pod_manifest = lib_helper.get_pod_manifest(
        'alp_cust.jsonnet', pod_input['name'], pod_input.get('namespace'),
        pod_input.get('labels'), pod_input.get('image'), pod_input.get(
            'node', ''))
    pod = lib.create_resource(pod_manifest, base_fixture)
    label_str = ''
    for k, v in pod['add_label'].items():
        label_str += k + '=' + v + ','
    pod['label_str'] = label_str[:-1]
    return pod


def check_traffic_from_pod_to_svc(pod, svc):
    kapi = KubeAPI()
    _pod = kapi.get_detail('pod',
                           **{'labels': pod['label_str']})['items'][0]
    svc_detail = lib.get_detail('service',
                                name=svc['name'],
                                namespace=svc['namespace'])
    LOG.info("Generating traffic from pod - [%s] to service - [%s] IP [%s]" % (
        _pod['metadata']['name'], svc['name'], svc_detail['spec']['clusterIP'])
             )
    lib.generate_traffic(_pod['metadata']['name'],
                         svc_detail['spec']['clusterIP'],
                         svc_detail['spec']['ports'][0]['port'],
                         _pod['metadata']['namespace'])
