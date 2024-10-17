import pytest
import time
import yaml
import random
import threading
import subprocess

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.conftest import gen_template_name
from tests import test_snat
from tests import (
    lib, validate_snat_apic_resource, lib_helper)
from tests.input.cfg import APIC_VALIDATION
from tests.lib_helper import get_template, dump_template
from tests.template_utils import env

from tests.input.cfg import (POLICY_COUNT,
                             ITERATIONS)

LOG = logger.get_logger(__name__)
CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'
EXEC_TIMEOUT = 180


class ThreadFailed(Exception):
        pass

@pytest.fixture(scope="session", autouse=True)
def update_hpp_direct(request):
    controller_value, hostagent_value = lib.get_enable_hpp_direct_controller_and_hostagent_current_value(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE)
    hpp_direct = request.config.getoption("--hpp_direct")
    if hpp_direct == "true":
        LOG.info("Network policies tests will be running with enable-hpp-direct enabled")
        lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
        lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
    else:
        LOG.info("Network policies tests will be running with enable-hpp-direct disabled")
        lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)
        lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)

    request.addfinalizer(lambda: set_default_hpp_direct(controller_value, hostagent_value))


def set_default_hpp_direct(controller_value, hostagent_value):
    LOG.info("Setting default enable-hpp-direct value :  False")
    lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, controller_value)
    lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, hostagent_value)


def update_hpp_optimization(hpp_opt):
    if hpp_opt:
        lib.update_hpp_optimization_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
        lib.update_hpp_optimization_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
    else:
        lib.update_hpp_optimization_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)
        lib.update_hpp_optimization_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)


@pytest.mark.usefixtures("clean_gen_templates")
def test_hpp_optimization_stress(base_fixture, gen_template_name):
    # create and delete network policies of same spec in parallel
    # to check if there are races
    def create_delete_nps(kapi, total_threads, fixture, gen_template_name, count, iterations):
        # create and delete network policies in loop
        policy_name = "allow-from-ns"
        for _itr in range(iterations):
            for _count in range(count):
                ns_name = "test-thread1-%s" % (_count)
                create_ns(fixture, gen_template_name, ns_name)
                create_np(fixture, policy_name, ns_name)

            for _count in range(count):
                ns_name = "test-thread1-%s" % (_count)
                cleanup(kapi, "networkpolicy", policy_name, ns_name)
                delete_ns(ns_name)
        LOG.info("Thread1 passed")
        threadLock.acquire()
        total_threads.remove("thread1")
        threadLock.release()

    def validate_traffic_of_new_nps(kapi, total_threads, fixture, gen_template_name, iterations, test1_ns_pod, test2_ns_pod):
        # create new network policy
        # validate traffic
        # delete network policy
        # repeat
        policy_name = "allow-from-ns"
        rsrc_name = "test-allow-from-ns"
        deploy_name = "test-allow-from-ns-nginx-deploy"
        svc_name = "test-allow-from-ns-nginx-svc"
        for _itr in range(iterations):
            ns_name = "test-thread2"
            create_ns(fixture, gen_template_name, ns_name)
            create_np(fixture, policy_name, ns_name)
            deployment, svc = _get_input_for_svc_and_deployment(
            name=rsrc_name, namespace=ns_name, selector={'app': 'web'})
            service = _deploy_svc(fixture, deployment, gen_template_name, svc, namespace=ns_name)
            with pytest.raises(subprocess.TimeoutExpired):
                lib.check_no_nw_connection_from_pod(
                    test1_ns_pod['name'], src_ip=None,
                targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
                      namespace='np-stress-test1')
            lib.check_nw_connection_from_pod(
                test2_ns_pod['name'], src_ip=None,
                targets=[(service['spec']['clusterIP'],
                    service['spec']['ports'][0]['port'])],
                    namespace='np-stress-test2')
            cleanup(kapi, "deployment", deploy_name, ns_name)
            cleanup(kapi, "service", svc_name, ns_name)
            cleanup(kapi, "networkpolicy", policy_name, ns_name)
            delete_ns(ns_name)
        LOG.info("Thread2 passed")
        threadLock.acquire()
        total_threads.remove("thread2")
        threadLock.release()

    def validate_traffic_of_existing_nps(kapi, total_threads, fixture, gen_template_name, iterations, test1_ns_pod, test2_ns_pod):
        # create network policy
        # validate traffic in loop
        # delete network policy
        rsrc_name = "test-allow-from-ns"
        deploy_name = "test-allow-from-ns-nginx-deploy"
        svc_name = "test-allow-from-ns-nginx-svc"
        policy_name = "allow-from-ns"
        ns_name = "test-thread3"
        create_ns(fixture, gen_template_name, ns_name)
        create_np(fixture, policy_name, ns_name)
        deployment, svc = _get_input_for_svc_and_deployment(
        name=rsrc_name, namespace=ns_name, selector={'app': 'web'})
        service = _deploy_svc(fixture, deployment, gen_template_name, svc, namespace=ns_name)

        for _itr in range(iterations):
            with pytest.raises(subprocess.TimeoutExpired):
                lib.check_no_nw_connection_from_pod(
                    test1_ns_pod['name'], src_ip=None,
                    targets=[(service['spec']['clusterIP'],
                          service['spec']['ports'][0]['port'])],
                          namespace='np-stress-test1')
            lib.check_nw_connection_from_pod(
                test2_ns_pod['name'], src_ip=None,
                    targets=[(service['spec']['clusterIP'],
                    service['spec']['ports'][0]['port'])],
                    namespace='np-stress-test2')
        
        cleanup(kapi, "deployment", deploy_name, ns_name)
        cleanup(kapi, "service", svc_name, ns_name)
        cleanup(kapi, "networkpolicy", policy_name, ns_name)
        delete_ns(ns_name)
        LOG.info("Thread3 passed")
        threadLock.acquire()
        total_threads.remove("thread3")
        threadLock.release()

    update_hpp_optimization(True)
    kapi = KubeAPI()
    print("Number of iterations: " + str(ITERATIONS))
    print("Number of policy count: " + str(POLICY_COUNT))
    test1_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'np-stress-test1', labels={'purpose': 'testing1'})
    lib.create_resource(test1_ns_manifest, base_fixture)
    test2_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'np-stress-test2', labels={'purpose': 'testing2'})
    lib.create_resource(test2_ns_manifest, base_fixture)
    test1_ns_pod = _create_pod(
        base_fixture, get_input('test1-ns-pod', namespace='np-stress-test1'))
    test2_ns_pod = _create_pod(
        base_fixture, get_input('test2-ns-pod', namespace='np-stress-test2'))

    threadLock = threading.Lock()
    total_threads = ["thread1", "thread2", "thread3"]
    t1 = threading.Thread(target=create_delete_nps, args=(kapi, total_threads, base_fixture, gen_template_name, ITERATIONS, int(POLICY_COUNT/2)))
    t2 = threading.Thread(target=validate_traffic_of_new_nps, args=(kapi, total_threads, base_fixture, gen_template_name, int(POLICY_COUNT/4), test1_ns_pod, test2_ns_pod))
    t3 = threading.Thread(target=validate_traffic_of_existing_nps, args=(kapi, total_threads, base_fixture, gen_template_name, int(POLICY_COUNT/2), test1_ns_pod, test2_ns_pod))

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    update_hpp_optimization(False)

    if len(total_threads) > 0:
        for i in range(len(total_threads)):
            LOG.error("%s Failed " % total_threads[i])
        raise ThreadFailed


def create_np(fixture, policy_name, ns_name):
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        policy_name,
        namespace=ns_name,
        ingress=True,
        ingress_rules=[
            {"from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "purpose": "testing2"
                    }
                }}]
             }
        ]
    )
    return lib.create_resource(policy_manifest, fixture)


def _create_pod(base_fixture, pod_input): 
    pod_manifest = lib_helper.get_pod_manifest( 
        'alp.jsonnet', pod_input['name'], pod_input.get('namespace'), 
        pod_input.get('labels'))
    return lib.create_resource(pod_manifest, base_fixture)


def get_input(name, generate_name=None, labels=None, namespace=None):
    arguments = locals()
    return {k: arguments[k] for k in list(arguments.keys()) if arguments[k]
            is not None}


def _get_input_for_svc_and_deployment(name, namespace='default',
                                      selector=None, non_root=False,
                                      tport=8080, port_name=None):
    replicas = lib_helper.get_cluster_node_count()
    deployment = {                           
        'name': '%s-nginx-deploy' % name,
        'template': 'nginx_deployment.yaml',
        'kind': 'deployment',
        'replicas': replicas,
        'namespace': namespace
    }   
    svc = { 
        'name': '%s-nginx-svc' % name,
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'namespace': namespace,
        'target_port': tport    
    }                       
    if port_name:
        deployment['port_name'] = svc['port_name'] = port_name
    if selector:
        deployment['selector'] = svc['selector'] = selector
    if non_root:
        deployment['template'] = 'nginx_non_root_deployment.yaml'
    return deployment, svc


def _get_policy_input(name, template, namespace='default'):
    policy = {               
        'name': name,
        'namespace': namespace,
        'template': template
    }
    return policy


def delete_ns(ns):
    try:
        LOG.info("Deleting Namespace:%s" % ns)
        cmd = "kubectl delete ns %s " % ns
        _execute(cmd.split())
    except Exception as err:
        print("Error : Deletion ns failed for : ", ns, err)


def _deploy_svc(base_fixture, deployment, gen_template_name, svc,
                namespace='default'):
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    return lib.get_detail('service', svc['name'], namespace=namespace)


def create_ns(fixture, gen_template_name, name):
    rsc = _get_input_for_namespace(name)
    template = env.get_template(rsc['template'])
    rend_temp = template.render(input=rsc)
    temp_name = gen_template_name(rsc['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, fixture)


def _execute(cmd):
    process_output = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    output, err = process_output.communicate(timeout=EXEC_TIMEOUT)
    if process_output.returncode != 0:
        raise Exception(err)
    output = yaml.safe_load(output)
    return output


def cleanup(kapi, obj_type, name, ns):
    LOG.info("Deleting %s %s in ns %s " % (obj_type, name, ns))
    try:
        if obj_type == "networkpolicy":
            cmd = "kubectl delete %s -n %s -l test=test-%s" % (obj_type, ns, name)
            _execute(cmd.split())
        else:
            cmd = "kubectl delete %s -n %s %s" % (obj_type, ns, name)
            _execute(cmd.split())
    except Exception as err:
        LOG.error("deletion failed: %s" % err)


def _get_input_for_namespace(name):
    return {
        'name': name,        
        'kind': 'Namespace', 
        'template': 'namespace.yaml'
    }
