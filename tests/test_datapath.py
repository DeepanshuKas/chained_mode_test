import os
import yaml
import pytest
import socket
import ipaddress
import random
import json

from acc_pyutils import logger, utils
from acc_pyutils.acc_cfg import get_kube_client
from acc_pyutils.api import KubeAPI
from tests import lib, lib_helper
from tests.input.cfg import EXTERNAL_IP_POOL,OPENSHIFT_BASE_DOMAIN,APIC_PROVISION_FILE
from tests.template_utils import env
from tests.server_utils import ServerUtils
from tests.test_chained_mode import check_chained_mode

SRV_UTILS = ServerUtils()
LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')


@pytest.mark.skip(reason="covered functionality with daemonset tests")
@pytest.mark.usefixtures("clean_gen_templates")
def test_loadbalancing(base_fixture, gen_template_name):
    selector = {'name': 'test-lb'}
    deploy_in = {'name': 'tlb-nginx-deploy'}
    svc_in = {'name': 'tlb-nginx-svc'}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector)
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'deployment', svc.get('namespace', 'default'))



def create_or_update_service(svc_name, selector, base_fixture, gen_template_name, create, **kwargs):
    svc =  _get_input_for_service(svc_name, selector, **kwargs)
    template = env.get_template(svc['template'])
    rend_temp = template.render(input=svc)
    temp_name = gen_template_name(svc['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    if create:
        return lib.create_resource(temp_name, base_fixture)
    else:
        return lib.apply_resource(temp_name)

def update_service(svc_name, selector, base_fixture, gen_template_name, **kwargs):
    return create_or_update_service(svc_name, selector, base_fixture, gen_template_name, create=False, **kwargs)

def create_service(svc_name, selector, base_fixture, gen_template_name,**kwargs):
    return create_or_update_service(svc_name, selector, base_fixture, gen_template_name, create=True, **kwargs)


@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_loadbalancing_static_ip_basic(base_fixture, gen_template_name):
    '''
    1. Request static LB IP using annotation, it should be allocated
    2. Request same static LB IP again, it should not be allocated
    3. Delete svc, Request same static LB IP again, it should be allocated
    '''
    kapi = KubeAPI()
    static_ipv4, _ = lib_helper.get_random_ips_from_extern_subnet()
    test_lb_ip = [static_ipv4]

    LOG.info("Test LB IPs %s" % (test_lb_ip))
    svc_name = 'test-lb-svc-static'
    selector = {'name': svc_name}
    deploy_in = {'name': '%s-deploy' % svc_name}
    svc_in = {'name': svc_name}
    # Request static LB IP using annotation, it should be allocated
    deploy, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector, replicas=1, lb_ip_annotation=test_lb_ip)
    for rsc in [deploy, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    svc_info = lib_helper.get_svc_detail(svc['name'],
                                         svc.get('namespace', 'default'))
    LOG.info("Service Details : %s"% svc_info)
    svc_lb_ips = [svc_info.get('lb_ip')]
    assert (svc_lb_ips == test_lb_ip) , (
        "Service %s static lb_ips %s not matching with expected ips %s" %
        (svc_info['name'], svc_lb_ips, test_lb_ip))
    LOG.info("Validate LB Static IPs SUCCESS %s" % test_lb_ip)
    # Verify SVC traffic
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace', 'default'))

    # Request same static LB IP again, it should not be allocated
    svc_name = 'test-lb-svc-static-1'
    svc_1 = create_service(svc_name, selector, base_fixture, gen_template_name,
                          lb_ip_annotation=test_lb_ip)
    svc_info = lib_helper.get_svc_detail(svc_1['name'],
                                         svc_1.get('namespace', 'default'))
    LOG.info("Service Details : %s"% svc_info)
    svc_lb_ips = [svc_info.get('lb_ip')]
    assert (svc_lb_ips != test_lb_ip) , (
        "Service %s static lb_ips %s should not match expected ips %s" %
        (svc_info['name'], svc_lb_ips, test_lb_ip))
    LOG.info("Validate LB Static IPs SUCCESS %s" % test_lb_ip)

    # Delete svc, Request same static LB IP again, it should be allocated
    """Deleting the resources"""
    LOG.info("Deleting %s" % svc['name'])
    kapi.delete_object('svc', svc['name'], svc.get('namespace', 'default'))
    svc_name = 'test-lb-svc-static-2'
    svc_2 = create_service(svc_name, selector, base_fixture, gen_template_name,
                           lb_ip_annotation=test_lb_ip)
    svc_info = lib_helper.get_svc_detail(svc_2['name'],
                                         svc_2.get('namespace', 'default'))
    LOG.info("Service Details : %s"% svc_info)
    svc_lb_ips = [svc_info.get('lb_ip')]
    assert (svc_lb_ips == test_lb_ip) , (
        "Service %s static lb_ips %s not matching with expected ips %s" %
        (svc_info['name'], svc_lb_ips, test_lb_ip))
    LOG.info("Validate LB Static IPs SUCCESS %s" % test_lb_ip)

    # Verify SVC traffic
    lib_helper.verify_svc_traffic(
        svc_2['name'], selector, 'traffic_validation', svc_2.get('namespace', 'default'))


@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_loadbalancing_static_ip_update(base_fixture, gen_template_name):
    extern_static, extern_dynemic = lib_helper.get_extern_subnets_from_cm()
    selector = {'name': 'test-lb'}
    deploy_in = {'name': 'tlb-nginx-deploy'}
    svc_in = {'name': 'tlb-nginx-svc'}
    static_ipv4 = str(lib_helper.get_random_ip_within_subnet(extern_static[0]))

    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector, load_balancer_ip=static_ipv4)
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    
    ext_ip_before_update = lib_helper.get_svc_detail(svc['name'])['lb_ip']

    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace', 'default'))

    static_ipv4 = str(ipaddress.IPv4Address(static_ipv4) + 1)
    update_service(svc['name'], selector, base_fixture, gen_template_name,
                          load_balancer_ip=static_ipv4)

    ext_ip_after_update = lib_helper.get_svc_detail(svc['name'])['lb_ip']

    assert ext_ip_before_update != ext_ip_after_update, "Static IP update failed"

    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace', 'default'))

    # Invalid IP (using from dynamic pool)
    static_ipv4 = str(lib_helper.get_random_ip_within_subnet(extern_dynemic[0]))
    update_service(svc['name'], selector, base_fixture, gen_template_name,
                          load_balancer_ip=static_ipv4)

    ext_ip_after_update = lib_helper.get_svc_detail(svc['name'])['lb_ip']
    # IP should not be assigned from dynamic pool
    assert ext_ip_after_update != static_ipv4, "Static IP update failed"
    
    # invalid IP - Using network address
    network = ipaddress.IPv4Network(extern_static[0], strict=False)
    static_ipv4 = str(network.network_address)
    update_service(svc['name'], selector, base_fixture, gen_template_name,
                          load_balancer_ip=static_ipv4)

    ext_ip_after_update = lib_helper.get_svc_detail(svc['name'])['lb_ip']
    # IP should not be assigned as not in range
    assert ext_ip_after_update != static_ipv4, "Static IP update failed"
   

@pytest.mark.xfail
@pytest.mark.usefixtures("clean_gen_templates")
def test_node_port(base_fixture, gen_template_name):
    selector = {'name': 'test-lb'}
    deploy_in = {'name': 'tlb-nginx-deploy'}
    svc_in = {'name': 'tlb-nginx-svc'}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector, lb_type='NodePort')
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'nodeport', svc.get('namespace', 'default'))


@pytest.mark.usefixtures("clean_gen_templates")
def test_pod_connectivity(base_fixture, gen_template_name):
    kapi, pods = KubeAPI(), {}
    for _pod in ['alp1', 'alp2']:
        pod_input = {'name': _pod,
                     'labels': {'tpc': 'ping-pod'},
                     'image': 'noiro-quay.cisco.com/noiro/alpine-utils:latest'}
        pod = create_pod(pod_input, base_fixture)
        pods[_pod] = kapi.get_detail(
            'pod', **{'labels': pod['label_str']})['items'][0]

    p1_name, p2_name = (pods['alp1']['metadata']['name'],
                        pods['alp2']['metadata']['name'])
    pods[p1_name], pods[p2_name] = (pods.pop('alp1'), pods.pop('alp2'))
    LOG.info("Testing ping traffic between pods %s %s"% (p1_name, p2_name))
    for p_name in [p1_name, p2_name]:
        dst_pod = list({p1_name, p2_name} - {p_name})[0]
        tip = lib_helper.get_pod_ip(
            dst_pod, pods[dst_pod]['metadata']['namespace'])
        lib_helper.check_ping_from_pod(
            p_name, pods[p_name]['metadata']['namespace'], tip,
            target='pod')


@pytest.mark.xfail
@pytest.mark.usefixtures("clean_gen_templates")
def test_daemonset_connectivity(base_fixture, gen_template_name):
    selector = {'name': 'test-dsc-datapath'}
    daemonset = _get_input_for_daemonset('tdc-nginx-ds', selector)
    svc = _get_input_for_service('tdc-nginx-service', selector)
    for rsrc in [daemonset, svc]:
        template = env.get_template(rsrc['template'])
        rend_template = template.render(input=rsrc)
        temp_name = gen_template_name(rsrc['name'])
        lib_helper.dump_template(temp_name, rend_template)
        lib.create_resource(temp_name, base_fixture)
    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'daemonset', svc.get('namespace', 'default'))


@pytest.mark.smoke
@pytest.mark.usefixtures("clean_gen_templates")
def test_ew_traffic(base_fixture, gen_template_name):
    kapi = KubeAPI()
    selector = {'name': 'test-ew-traffic'}
    daemonset = _get_input_for_daemonset('tewt-nginx-ds', selector)
    # TODO(VK): refactor
    src_pod_input = {'name': 'ew-traffic-tester',
                     'labels': {'tewt': 'ping-pod'},
                     'image': 'noiro-quay.cisco.com/noiro/alpine-utils:latest'}
    src_pod = create_pod(src_pod_input, base_fixture)
    src_pod = kapi.get_detail(
        'pod', **{'labels': src_pod['label_str']})['items'][0]

    for rsrc in [daemonset]:
        template = env.get_template(rsrc['template'])
        rend_template = template.render(input=rsrc, pod=rsrc)
        temp_name = gen_template_name(rsrc['name'])
        lib_helper.dump_template(temp_name, rend_template)
        lib.create_resource(temp_name, base_fixture)
    pods = lib_helper.get_pods_by_labels(selector)
    for _pod in pods:
        lib_helper.check_ping_from_pod(
            src_pod['metadata']['name'],
            src_pod['metadata']['namespace'],
            _pod[1])


@pytest.mark.usefixtures("clean_gen_templates")
def test_cross_ns_service_traffic(base_fixture, gen_template_name):
    deploy_9_in = {'name': 'nginx-deploy',
                   'namespace': 'test9',
                   'label': {'app': 'nginx-deploy-9'}}
    deploy_10_in = {'name': 'nginx-deploy',
                    'namespace': 'test10',
                    'label': {'app': 'nginx-deploy-10'}}
    svc_9_in = {'name': 'nginx-service', 'namespace': 'test9'}
    svc_10_in = {'name': 'nginx-service', 'namespace': 'test10'}
    selector_9 = {'app': 'nginx-test-9'}
    selector_10 = {'app': 'nginx-test-10'}
    ns_9 = _get_input_for_namespace('test9')
    ns_10 = _get_input_for_namespace('test10')
    deploy_9, svc_9 = _get_input_for_svc_and_deployment(
        deploy_9_in, svc_9_in, selector_9)
    deploy_10, svc_10 = _get_input_for_svc_and_deployment(
        deploy_10_in, svc_10_in, selector_10)
    for rsc in [ns_9, deploy_9, svc_9, ns_10, deploy_10, svc_10]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    def _create_test_pod(pod_in):
        pod_template = env.get_template(pod_in['template'])
        pod_rend_temp = pod_template.render(pod=pod_in)
        pod_temp_name = gen_template_name(pod_in['name'])
        lib_helper.dump_template(pod_temp_name, pod_rend_temp)
        lib.create_resource(pod_temp_name, base_fixture)

    test_pod_in = _get_input_for_pod('test-pod', namespace='test9')
    _create_test_pod(test_pod_in)
    # test svc traffic in same namespace ie test9 ns
    check_traffic_from_pod_to_svc(test_pod_in, svc_9_in)
    # test endpoint traffic in same namespace ie test9 ns
    check_traffic_from_pod_to_svc_endpoint(test_pod_in, svc_9_in)
    # test svc traffic in different namespace ie svc in test10 ns
    check_traffic_from_pod_to_svc(test_pod_in, svc_10_in)
    # test endpoint traffic in same namespace ie test10 ns
    check_traffic_from_pod_to_svc_endpoint(test_pod_in, svc_10_in)

@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_traffic_while_scale_up(base_fixture, gen_template_name):
    ns = _get_input_for_namespace('su-val')
    selector = {'test': 'su-dp-validation'}
    deploy_in = {'name': 'su-nginx-deploy', 'namespace': ns['name']}
    svc_in = {'name': 'su-nginx-svc', 'namespace': ns['name']}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector)
    for rsc in [ns, deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    lib.scale_deployment(
        deploy_in['name'], 9, ns['name'], wait_until_scale=False)

    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace',
                                                             'default'))

@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_traffic_while_scale_down(base_fixture, gen_template_name):
    ns = _get_input_for_namespace('sd-val')
    selector = {'test': 'sd-dp-validation'}
    deploy_in = {'name': 'sd-nginx-deploy', 'namespace': ns['name']}
    svc_in = {'name': 'sd-nginx-svc', 'namespace': ns['name']}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector)
    deployment['replicas'] = 5
    for rsc in [ns, deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    lib.scale_deployment(
        deploy_in['name'], 1, ns['name'], wait_until_scale=False)

    lib_helper.verify_svc_traffic(
        svc['name'], selector, 'traffic_validation', svc.get('namespace',
                                                             'default'))


@pytest.mark.usefixtures("clean_gen_templates")
def test_ew_traffic_while_scale_up(base_fixture, gen_template_name):
    ns = _get_input_for_namespace('ew-su-val')
    pod1 = _get_input_for_pod('ew-su-tt1', namespace=ns['name'])
    pod2 = _get_input_for_pod('ew-su-tt2', namespace=ns['name'])
    pod3 = _get_input_for_pod('ew-su-tt3', namespace=ns['name'])

    selector = {'test': 'ew-su-validation'}
    deploy_in = {'name': 'ew-su-nginx-deploy', 'namespace': ns['name']}
    svc_in = {'name': 'ew-su-nginx-svc', 'namespace': ns['name']}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector)
    for rsc in [ns, deployment, svc, pod1, pod2, pod3]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc) if not rsc['kind'] == 'pod' \
            else template.render(pod=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    lib.scale_deployment(
        deploy_in['name'], 9, ns['name'], wait_until_scale=False)

    _generate_traffic_from_pods_to_svc(
        [pod1, pod2, pod3], svc_in, no_of_runs=3)


@pytest.mark.usefixtures("clean_gen_templates")
def test_ew_traffic_while_scale_down(base_fixture, gen_template_name):
    ns = _get_input_for_namespace('ew-sd-val')
    pod1 = _get_input_for_pod('ew-sd-tt1', namespace=ns['name'])
    pod2 = _get_input_for_pod('ew-sd-tt2', namespace=ns['name'])
    pod3 = _get_input_for_pod('ew-sd-tt3', namespace=ns['name'])

    selector = {'test': 'ew-sd-validation'}
    deploy_in = {'name': 'ew-sd-nginx-deploy', 'namespace': ns['name']}
    svc_in = {'name': 'ew-sd-nginx-svc', 'namespace': ns['name']}
    deployment, svc = _get_input_for_svc_and_deployment(
        deploy_in, svc_in, selector)
    deployment['replicas'] = 5
    for rsc in [ns, deployment, svc, pod1, pod2, pod3]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc) if not rsc['kind'] == 'pod' \
            else template.render(pod=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    lib.scale_deployment(
        deploy_in['name'], 1, ns['name'], wait_until_scale=False)

    _generate_traffic_from_pods_to_svc(
        [pod1, pod2, pod3], svc_in, no_of_runs=3)


@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for Chained mode test")
def test_comm_from_outside_to_app_thru_default_router(base_fixture):
    kapi = KubeAPI()
    try:
        ocp_route = _create_common_resources(base_fixture)

        router_default = lib.get_detail('service', 'router-default',
                                        'openshift-ingress')
        router_sharded = lib.get_detail('service', 'router-sharded',
                                        'openshift-ingress')
        lib.check_os_route_status(ocp_route['name'], ocp_route['namespace'])
        route_detail = lib.get_detail('route', ocp_route['name'], ocp_route[
            'namespace'])

        LOG.info('default IP - %s' % router_default['status']['loadBalancer'][
            'ingress'][0]['ip'])
        LOG.info('Route - %s' % route_detail['status']['ingress'][0]['host'])
        LOG.info('sharded IP - %s' % router_sharded['status']['loadBalancer'][
            'ingress'][0]['ip'])

        lib.update_host_file("%s  %s" % (
            router_default['status']['loadBalancer']['ingress'][0]['ip'],
            route_detail['status']['ingress'][0]['host']),
                             "add")
        lib_helper.connect_with_source_ip(
            EXTERNAL_IP_POOL[0],
            'https://%s' % route_detail['status']['ingress'][0]['host'])
    finally:
        try:
            kapi.exec_cli_cmd(
                "oc delete -f %s/ocp-ingress-rshard-sharded-lb-svc.yaml" %
                DATA_DIR)
        except Exception as e:
            LOG.warn("Deletion of rshard-sharded-lb-svc.yaml failed. %s" % e)
        try:
            lib.update_host_file("%s  %s" % (
                router_default['status']['loadBalancer']['ingress'][0]['ip'],
                route_detail['status']['ingress'][0]['host']),
                                 "delete")
        except KeyError:
            pass


@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
def test_comm_from_inside_to_app_thru_default_router(base_fixture):
    kapi = KubeAPI()
    try:
        ocp_route = _create_common_resources(base_fixture)

        router_default = lib.get_detail('service', 'router-default',
                                        'openshift-ingress')
        router_sharded = lib.get_detail('service', 'router-sharded',
                                        'openshift-ingress')
        lib.check_os_route_status(ocp_route['name'], ocp_route['namespace'])
        route_detail = lib.get_detail('route', ocp_route['name'], ocp_route[
            'namespace'])

        LOG.info('default IP - %s' % router_default['status']['loadBalancer'][
            'ingress'][0]['ip'])
        LOG.info('Route - %s' % route_detail['status']['ingress'][0]['host'])
        LOG.info('sharded IP - %s' % router_sharded['status']['loadBalancer'][
            'ingress'][0]['ip'])

        lib.update_host_file("%s  %s" % (
            router_default['status']['loadBalancer']['ingress'][0]['ip'],
            route_detail['status']['ingress'][0]['host']),
                             "add")

        pod_input = {'name': 'tester', 'image': 'noiro-quay.cisco.com/noiro/alp-curl'}
        pod = create_pod(pod_input, base_fixture)

        pod = kapi.get_detail('pod',
                              **{'labels': pod['label_str']})['items'][0]

        kapi.kexec(pod['metadata']['name'],
                   'curl -k https://%s' % route_detail['status']['ingress'][0][
                       'host'],
                   interpreter='sh -c')
    finally:
        try:
            kapi.exec_cli_cmd(
                "oc delete -f %s/ocp-ingress-rshard-sharded-lb-svc.yaml" %
                DATA_DIR)
        except Exception as e:
            LOG.warn("Deletion of rshard-sharded-lb-svc.yaml failed. %s" % e)
        try:
            lib.update_host_file("%s  %s" % (
                router_default['status']['loadBalancer']['ingress'][0]['ip'],
                route_detail['status']['ingress'][0]['host']),
                                 "delete")
        except KeyError:
            pass


@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
def test_comm_from_outside_to_app_using_sharded_router(base_fixture):
    kapi = KubeAPI()
    try:
        kapi.apply_label('ns', True, None, 'default', 'environment=shard',
                         name='default')
        ocp_route = _create_common_resources(base_fixture)

        router_default = lib.get_detail('service', 'router-default',
                                        'openshift-ingress')
        router_sharded = lib.get_detail('service', 'router-sharded',
                                        'openshift-ingress')
        lib.check_os_route_status(ocp_route['name'], ocp_route['namespace'])
        route_detail = lib.get_detail('route', ocp_route['name'], ocp_route[
            'namespace'])

        LOG.info('default IP - %s' % router_default['status']['loadBalancer'][
            'ingress'][0]['ip'])
        LOG.info('Route - %s' % route_detail['status']['ingress'][0]['host'])
        LOG.info('sharded IP - %s' % router_sharded['status']['loadBalancer'][
            'ingress'][0]['ip'])

        lib.update_host_file("%s  %s" % (
            router_sharded['status']['loadBalancer']['ingress'][0]['ip'],
            route_detail['status']['ingress'][0]['host']),
                             "add")
        lib_helper.connect_with_source_ip(
            EXTERNAL_IP_POOL[0],
            'https://%s' % route_detail['status']['ingress'][0]['host'])
    finally:
        try:
            kapi.delete_label('ns', 'default', 'environment-', name='default')
        except Exception as e:
            LOG.warn('Failed to remove label environment=shard from default '
                     'namespace %s' % e)
        try:
            kapi.exec_cli_cmd(
                "oc delete -f %s/ocp-ingress-rshard-sharded-lb-svc.yaml" %
                DATA_DIR)
        except Exception as e:
            LOG.warn("Deletion of rshard-sharded-lb-svc.yaml failed. %s" % e)
        try:
            lib.update_host_file("%s  %s" % (
                router_sharded['status']['loadBalancer']['ingress'][0]['ip'],
                route_detail['status']['ingress'][0]['host']),
                                 "delete")
        except KeyError:
            pass


@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode test")
def test_comm_from_inside_to_app_using_sharded_router(base_fixture):
    kapi = KubeAPI()
    try:
        kapi.apply_label('ns', True, None, 'default', 'environment=shard',
                         name='default')
        ocp_route = _create_common_resources(base_fixture)

        router_default = lib.get_detail('service', 'router-default',
                                        'openshift-ingress')
        router_sharded = lib.get_detail('service', 'router-sharded',
                                        'openshift-ingress')
        lib.check_os_route_status(ocp_route['name'], ocp_route['namespace'])
        route_detail = lib.get_detail('route', ocp_route['name'], ocp_route[
            'namespace'])

        LOG.info('default IP - %s' % router_default['status']['loadBalancer'][
            'ingress'][0]['ip'])
        LOG.info('Route - %s' % route_detail['status']['ingress'][0]['host'])
        LOG.info('sharded IP - %s' % router_sharded['status']['loadBalancer'][
            'ingress'][0]['ip'])

        lib.update_host_file("%s  %s" % (
            router_sharded['status']['loadBalancer']['ingress'][0]['ip'],
            route_detail['status']['ingress'][0]['host']),
                             "add")

        pod_input = {'name': 'tester', 'image': 'noiro-quay.cisco.com/noiro/alp-curl'}
        pod = create_pod(pod_input, base_fixture)
        pod = kapi.get_detail('pod',
                              **{'labels': pod['label_str']})['items'][0]

        kapi.kexec(pod['metadata']['name'],
                   'curl -k https://%s' % route_detail['status']['ingress'][0][
                       'host'],
                   interpreter='sh -c')
    finally:
        try:
            kapi.delete_label('ns', 'default', 'environment-', name='default')
        except Exception as e:
            LOG.warn('Failed to remove label environment=shard from default '
                     'namespace - %s' % e)
        try:
            kapi.exec_cli_cmd(
                "oc delete -f %s/ocp-ingress-rshard-sharded-lb-svc.yaml" %
                DATA_DIR)
        except Exception as e:
            LOG.warn("Deletion of rshard-sharded-lb-svc.yaml failed. %s" % e)
        try:
            lib.update_host_file("%s  %s" % (
                router_sharded['status']['loadBalancer']['ingress'][0]['ip'],
                route_detail['status']['ingress'][0]['host']),
                                 "delete")
        except KeyError:
            pass


@pytest.mark.smoke
@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
def test_openshift_console_access(base_fixture):
    LOG.info("Test Openshift console access")
    acc_provision_input = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    c_info = lib_helper.get_resource_details_from_acc_provision_input_file(acc_provision_input)
    system_id =  c_info['system_id']
    baseDomain = OPENSHIFT_BASE_DOMAIN

    install_config_path = os.path.abspath('tests/input/install-config.yaml')
    if os.path.exists(install_config_path):
        with open(install_config_path, 'r') as file:
            install_config = yaml.safe_load(file)
            baseDomain = install_config['baseDomain']

    cmd = "curl -s -o /dev/null -w %{http_code} \
        "+"https://api.{}.{}".format(system_id,baseDomain)+":6443 -k --connect-timeout 60 --retry 2"

    ip_addr = socket.gethostbyname('api.{}.{}'.format(system_id,baseDomain))
    try:
       openStackFloatingIp = install_config['platform']['openstack']['lbFloatingIP']
       if openStackFloatingIp == "" or openStackFloatingIp != ip_addr: 
           LOG.error("ip of api.openupi.noiro.local does not match with OpenStack floating IP associated with the API VIP")
    except:
         pass 
    try:
        output = SRV_UTILS.get_external_router().run(cmd)
        if output.stdout == "200":
            LOG.info("Openshift router is reachable !!")
        else:
            LOG.error("Accessed the OC routers, but the backend \
                communication is broken, which could be a DNS issue \
                or internal cluster communication issue. ")
    except Exception as e:
        LOG.error(" Openshift router is not reachable ! Error - %s", e)

def _delete_common_resources(base_fixture):
    kapi = KubeAPI()
    try:
        kapi.exec_cli_cmd(
            "oc delete -f {}/ocp-ingress-rshard-ingctrl.yaml".format(DATA_DIR))
        kapi.exec_cli_cmd(
            "oc delete -f {}/ocp-ingress-rshard-route.yaml".format(DATA_DIR))
        kapi.exec_cli_cmd(
            "oc delete -f {}/ocp-ingress-rshard-sharded-lb-svc.yaml".format(DATA_DIR))
        kapi.exec_cli_cmd(
            "oc delete -f {}/ocp-ingress-rshard-svc.yaml".format(DATA_DIR))
        kapi.exec_cli_cmd(
            "oc delete -f {}/ocp-ingress-rshard-deploycfg.yaml".format(DATA_DIR))
    except Exception as e:
        if 'not found' in str(e):
            LOG.warning("The resource does not exist %s. Skipping deletion..." % e)
        else:
            raise

def _create_common_resources(base_fixture):
    kapi = KubeAPI()
    lib.create_resource(
        '{}/ocp-ingress-rshard-deploycfg.yaml'.format(DATA_DIR), base_fixture)
    lib.create_resource('{}/ocp-ingress-rshard-svc.yaml'.format(
        DATA_DIR), base_fixture)
    # REVISIT(VK) - This is the case where framework svc create validation
    # doesn't pass. Time being we will execute this directly from cli. Need
    # to handle cases like this.
    # ocp_lb_svc = lib.create_resource(
    #     '{}/ocp-ingress-rshard-sharded-lb-svc.yaml'.format(DATA_DIR),
    #     base_fixture)
    kapi.exec_cli_cmd(
        "oc create -f {}/ocp-ingress-rshard-sharded-lb-svc.yaml".format(
            DATA_DIR))
    ocp_route = lib.create_resource(
        '{}/ocp-ingress-rshard-route.yaml'.format(DATA_DIR), base_fixture)
    lib.create_resource(
        '{}/ocp-ingress-rshard-ingctrl.yaml'.format(DATA_DIR),
        base_fixture)
    return ocp_route


def create_pod(pod_input, base_fixture):
    pod_manifest = lib_helper.get_pod_manifest(
        'alp_cust.jsonnet', pod_input['name'], pod_input.get('namespace'),
        pod_input.get('labels'), pod_input.get('image'))
    pod = lib.create_resource(pod_manifest, base_fixture)
    label_str = ''
    for k, v in pod['add_label'].items():
        label_str += k + '=' + v + ','
    pod['label_str'] = label_str[:-1]
    return pod


def check_traffic_from_pod_to_svc(pod, svc):
    svc_detail = lib.get_detail('service',
                                name=svc['name'],
                                namespace=svc['namespace'])
    LOG.info("Generating traffic from pod - [%s] to service - [%s] IP [%s]" % (
        pod['name'], svc['name'], svc_detail['spec']['clusterIP']))
    lib.generate_traffic(pod['name'],
                         svc_detail['spec']['clusterIP'],
                         svc_detail['spec']['ports'][0]['port'],
                         pod['namespace'])


def check_traffic_from_pod_to_svc_endpoint(pod, svc):
    endpoint = lib.get_detail('endpoints',
                              name=svc['name'],
                              namespace=svc['namespace'])

    for ep in endpoint['subsets'][0]['addresses']:
        LOG.info("Generating traffic from pod - [%s] to service - ["
                 "%s] endpoint IP [%s]" % (pod['name'], svc['name'], ep['ip']))
        lib.generate_traffic(pod['name'],
                             ep['ip'],
                             endpoint['subsets'][0]['ports'][0]['port'],
                             pod['namespace'])


def _generate_traffic_from_pods_to_svc(pods, svc_in, no_of_runs=1):
    while no_of_runs > 0:
        for pod in pods:
            check_traffic_from_pod_to_svc(pod, svc_in)
        no_of_runs -= 1


def _get_input_for_svc_and_deployment(deploy, svc, selectors, **kwargs):
    if kwargs.get('replicas'):
        replicas = kwargs.get('replicas')
    else:
        replicas = lib_helper.get_cluster_node_count()
    default_label = {'key': 'test', 'val': 'test_dp'}
    deployment = {
        'name': deploy['name'],
        'namespace': deploy.get('namespace', 'default'),
        'label': deploy.get('label', default_label),
        'template': 'nginx_deployment.yaml',
        'kind': 'deployment',
        'replicas': replicas
    }
    svc = {
        'name': svc['name'],
        'namespace': svc.get('namespace', 'default'),
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'lb_type': kwargs.get('lb_type', 'LoadBalancer')
    }
    if selectors:
        deployment['selector'] = selectors
        svc['selector'] = selectors
    if kwargs.get('load_balancer_ip', None) is not None:
        svc['load_balancer_ip'] = kwargs.get('load_balancer_ip')
    elif kwargs.get('lb_ip_annotation', None) is not None:
        svc['lb_ip_annotation'] = kwargs.get('lb_ip_annotation')
    if deploy.get('node', None) is not None:
        deployment['node'] = deploy.get('node')
    return deployment, svc


def _get_input_for_daemonset(name, selectors, **kwargs):
    return {
        'name': name,
        'namespace': kwargs.get('namespace', 'default'),
        'template': 'nginx_ds.yaml',
        'kind': 'daemonset',
        'selector': selectors if selectors else None,
        'runonmaster': kwargs.get('runonmaster', False)
    }


def _get_input_for_service(name, selectors, **kwargs):
    svc = {
        'name': name,
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'lb_type': kwargs.get('lb_type', 'LoadBalancer')
    }
    if selectors:
        svc['selector'] = selectors
    if kwargs.get('load_balancer_ip', None) is not None:
        svc['load_balancer_ip'] = kwargs.get('load_balancer_ip')
    elif kwargs.get('lb_ip_annotation', None) is not None:
        svc['lb_ip_annotation'] = kwargs.get('lb_ip_annotation')
    return svc


def _get_input_for_pod(name, **kwargs):
    return {
        'name': name,
        'template': 'busybox.yaml',
        'kind': 'pod',
        'namespace': kwargs.get('namespace', 'default')
    }


def _get_input_for_namespace(name):
    return {
        'name': name,
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }
