import pytest
import time
import subprocess
import yaml

from random import randint
from threading import Thread

from acc_pyutils.api import KubeAPI
from tests.conftest import gen_template_name
from tests import test_snat
from tests import (
    lib, validate_snat_apic_resource, lib_helper)
from tests.input.cfg import APIC_VALIDATION
from tests.lib_helper import get_template, dump_template
from tests.template_utils import env

from tests.input.cfg import (POLICY_COUNT, ITERATIONS,
                             SLEEP_BETWEEN_ITERATIONS,
                             SNAT_STRESS_TRAFFIC_VALIDATION)


SNAT_POLICY_RESOURCES = []
NETWORK_POLICY_RESOURCES = []
DD = True
no_of_round = 1
EXEC_TIMEOUT = 180


def setup_module(module):
    lib.collect_profiling_data(test_name="test_stress_5", when="before-test-run")


def teardown_module(module):
    lib.collect_profiling_data(test_name="test_stress_5", when="after-test-run")
    lib.show_cpu_memory_usage_difference(test_name="test_stress_5")


@pytest.mark.usefixtures("clean_gen_templates")
def test_stresssnat_and_networkpolicy_for_deployment(base_fixture, gen_template_name):
    """ Creates namespace, deployment, service, snatpolicy and networkpolicy.
        Validates SNAT ep file and snat files.
        Delete all the snatpolicies and re-create all those policies.
    """

    def run_deployments(kapi, count, workers, worker_node, fixture, result, index):

        for _count in range(count):
            num = str(index)
            ns_name = "stress-ns-%s-%s" % (num, _count)

            global no_of_round
            if no_of_round < 2:
                n_rsc = _get_input_for_namespace(ns_name)
                n_template = env.get_template(n_rsc['template'])
                n_rend_temp = n_template.render(input=n_rsc)
                n_temp_name = gen_template_name(n_rsc['name'])
                lib_helper.dump_template(n_temp_name, n_rend_temp)
                lib.create_resource(n_temp_name, base_fixture)

            policy_name = "snatpolicy-%s-%s" % (num, _count)
            policy_ip = "%s.0.0.%s/32" % (10 + index, _count + 2)
            policy_label = "label-%s-%s" % (num, _count)
            policy_input = test_snat.get_policy_input(
                policy_name,
                {'name': policy_label},
                snat_ip=policy_ip,
                namespace=ns_name)
            policy_temp = get_template(policy_input, gen_template_name)
            policy = lib.create_resource(policy_temp, fixture)
            SNAT_POLICY_RESOURCES.append((policy_name, ns_name))

            # Creating network policies
            NetworkPolicy_templates = ["allow-from-ingress.yaml", "allow-from-monitoring.yaml", "allow-same-ns.yaml", "deny-all.yaml"]
            for policy_temp in NetworkPolicy_templates:
                policy_name = "%s-%s-%s" % (policy_temp[:-5], index, _count)
                create_NetworkPolicy(base_fixture, policy_name, policy_temp, ns_name)

            if no_of_round == 2:
                continue

            _iterations = 1
            for _iter in range(_iterations):
                # Random number of replicas for a deployment
                replicas = randint(1, workers)

                deployment_name = "nginx-deploy-%s-%s-%s" % (
                    num, _count, _iterations)
                deploy_in = {'name': deployment_name,
                             'replicas': replicas,
                             'node': worker_node,
                             'namespace': ns_name}
                deploy_label = "label-%s-%s" % (index, _count)
                selector = {'name': deploy_label}
                svc_name = "tlb-nginx-svc-%s-%s-%s" % (
                    num, _count, _iterations)
                dummy_svc_input = {'name': svc_name,
                                   'namespace': ns_name}
                deployment, svc = _get_input_for_svc_and_deployment_with_replicas(
                        deploy_in, dummy_svc_input, selector, replicas)
                template = env.get_template(deployment['template'])
                rend_temp = template.render(input=deployment)
                temp_name = gen_template_name(deployment['name'])
                dump_template(temp_name, rend_temp)
                deploy_resource = lib.create_resource(temp_name, fixture)

                # SNAT validation
                if SNAT_STRESS_TRAFFIC_VALIDATION:
                    _, labels, _, _ = lib.get_deployment_details(
                            name=deployment['name'],
                            namespace=deployment['namespace'])

                    snat_policy = lib.get_detail(
                        'SnatPolicy',
                        name=policy['name'],
                        namespace=policy['namespace'])
                    snat_ips = lib.get_allocated_snat_ips_from_policy(
                        snat_policy)
                    snat_ids = lib.get_snat_ids_from_policy(snat_policy)
                    lib.verify_null_mac_file_on_nodes()
                    if APIC_VALIDATION:
                        validate_snat_apic_resource.test_apic(snat_ips)

                    kwargs = {'labels': ','.join(labels)}
                    pods = kapi.get_detail('pod',
                                           namespace=ns_name,
                                           **kwargs)
                    for pod in pods['items']:
                        pod_uid = pod['metadata']['uid']
                        hostname = pod['spec']['nodeName']
                        lib.validate_pod_ep_file(
                            pod_uid,
                            hostname,
                            deploy_resource['manifest_dir'],
                            snat_ids=snat_ids)
                        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
                        lib.validate_snat_file_on_host_for_snat_ips(
                            hostname,
                            snat_ip_info,
                            policy['manifest_dir'],
                            snat_ips)

                time.sleep(SLEEP_BETWEEN_ITERATIONS)

            result[index] = True

    print("Running stress SNAT and NetworkPolicy test with policy count: " + str(POLICY_COUNT))
    print("Number of iterations: " + str(ITERATIONS))
    print("Sleep between iterations: " + str(SLEEP_BETWEEN_ITERATIONS))
    print("Validating SNAT resources: " + str(SNAT_STRESS_TRAFFIC_VALIDATION))
    policy_count = POLICY_COUNT
    worker_count = len(lib.get_worker_nodes_hostname())
    worker_node = lib.get_one_of_workers_with_ready_state()
    kapi = KubeAPI()
    number_of_threads = 5
    deployment_threads = [None] * number_of_threads
    deployment_results = [None] * number_of_threads
    if policy_count % 5 != 0:
        raise Exception("policy count need to be in multiple of 5.")
    no_of_policy_per_thread = policy_count // number_of_threads
    if no_of_policy_per_thread > 250:
        raise Exception(
            "Policy count limit is 1250.")
    global no_of_round
    while no_of_round <= 2:
        for idx in range(number_of_threads):
            deployment_threads[idx] = Thread(target=run_deployments,
                                             args=(kapi,
                                                   no_of_policy_per_thread,
                                                   worker_count,
                                                   worker_node,
                                                   base_fixture,
                                                   deployment_results,
                                                   idx))
            deployment_threads[idx].start()

        for idx in range(number_of_threads):
            deployment_threads[idx].join()

        if DD and no_of_round < 2:
            for _rsrc in SNAT_POLICY_RESOURCES:
                cleanup(kapi, "snatpolicy", _rsrc[0], _rsrc[1])
            for _rsrc in NETWORK_POLICY_RESOURCES:
                cleanup(kapi, "networkpolicy", _rsrc[0], _rsrc[1])
        no_of_round += 1


def _get_input_for_svc_and_deployment_with_replicas(
        deploy, svc, selectors, replicas, **kwargs):
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
    if deploy['node']:
        deployment['node'] = deploy['node']
    if selectors:
        deployment['selector'] = selectors
        svc['selector'] = selectors
    return deployment, svc


def create_NetworkPolicy(fixture, policy_name, template, namespace):
    policy_input = _get_policy_input(policy_name, template, namespace=namespace)
    lib.create_resource_from_template(policy_input, fixture)
    NETWORK_POLICY_RESOURCES.append((policy_name, namespace))


def _get_input_for_namespace(name):
    return {
        'name': name,
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }


def _get_policy_input(name, template, namespace='default'):
    policy = {
        'name': name,
        'namespace': namespace,
        'template': template
    }
    return policy


def cleanup(kapi, obj_type, d_pol, ns):
    try:
        cmd = "kubectl delete %s %s -n %s" % (obj_type, d_pol, ns)
        _execute(cmd.split())
    except Exception as err:
        print("Err: ", err)
        print("Deletion failed for : ", d_pol, ns)


def _execute(cmd):
    process_output = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    output, err = process_output.communicate(timeout=EXEC_TIMEOUT)
    if process_output.returncode != 0:
        raise Exception(err)
    output = yaml.safe_load(output)
    return output