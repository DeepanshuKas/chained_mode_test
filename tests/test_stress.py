import pytest
import time

from random import randint
from threading import Thread

from acc_pyutils.api import KubeAPI
from tests.conftest import gen_template_name
from tests import test_snat
from tests import lib, validate_snat_apic_resource, test_tuneup
from tests.input.cfg import APIC_VALIDATION
from tests.lib_helper import get_template, dump_template
from tests.template_utils import env


def setup_module(module):
    lib.collect_profiling_data(test_name="test_stress", when="before-test-run")


def teardown_module(module):
    lib.collect_profiling_data(test_name="test_stress", when="after-test-run")
    lib.show_cpu_memory_usage_difference(test_name="test_stress")


@pytest.mark.usefixtures("clean_gen_templates")
def test_stresssnat_for_deployment(base_fixture, gen_template_name):

    def run_deployments(kapi, count, worker_nodes, fixture, result, index):
        # In each iteration we create a deployment matching with policy no index and with random number of replicas
        num = str(index)
        policy_name = "simplepolicy-%s" % num
        policy_ip = "10.0.0.%s/32" % num
        policy_label = "label-%s" % num
        policy_input = test_snat.get_policy_input(policy_name,
                {'name': policy_label},
                snat_ip=policy_ip)
        policy_temp = get_template(policy_input, gen_template_name)
        policy = lib.create_resource(policy_temp, fixture)

        for iter in range(ITERATIONS):
            # Random number of replicas for a deployment
            replicas = randint(1, worker_nodes)

            deployment_name = "stress-nginx-deploy-" + str(index)
            deploy_in = {'name': deployment_name, 'replicas': replicas}
            deploy_label = "label-%s" % index
            selector = {'name': deploy_label}
            dummy_svc_input = {'name': 'tlb-nginx-svc'}
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
                        name=deployment['name'])

                snat_policy = lib.get_detail('SnatPolicy',
                                   name=policy['name'],
                                     namespace=policy['namespace'])
                snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
                snat_ids = lib.get_snat_ids_from_policy(snat_policy)
                lib.verify_null_mac_file_on_nodes()
                if APIC_VALIDATION:
                    validate_snat_apic_resource.test_apic(snat_ips)

                kwargs = {'labels': ','.join(labels)}
                pods = kapi.get_detail('pod', **kwargs)
                for pod in pods['items']:
                    pod_uid = pod['metadata']['uid']
                    hostname = pod['spec']['nodeName']
                    lib.validate_pod_ep_file(pod_uid,
                            hostname,
                            deploy_resource['manifest_dir'],
                            snat_ids=snat_ids)
                    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
                    lib.validate_snat_file_on_host_for_snat_ips(hostname,
                            snat_ip_info,
                            policy['manifest_dir'],
                            snat_ips)

            time.sleep(SLEEP_BETWEEN_ITERATIONS)
            kapi.delete_object('deployment', deployment['name'])

        result[index] = True
    
    from tests.input.cfg import (POLICY_COUNT, ITERATIONS, SLEEP_BETWEEN_ITERATIONS, SNAT_STRESS_TRAFFIC_VALIDATION)

    print("Running stress SNAT test with policy count: " + str(POLICY_COUNT))
    print("Number of iterations: " + str(ITERATIONS))
    print("Sleep between iterations: " + str(SLEEP_BETWEEN_ITERATIONS))
    print("Validating SNAT resources: " + str(SNAT_STRESS_TRAFFIC_VALIDATION))
    policy_count = POLICY_COUNT
    worker_count = len(lib.get_worker_nodes_hostname())
    kapi = KubeAPI()
    deployment_threads = [None] * policy_count
    deployment_results = [None] * policy_count
    for idx in range(policy_count):
        deployment_threads[idx] = Thread(target=run_deployments,
                        args=(kapi, policy_count, worker_count, base_fixture, deployment_results, idx))
        deployment_threads[idx].start()

    for idx in range(policy_count):
        deployment_threads[idx].join()


def _get_input_for_svc_and_deployment_with_replicas(deploy, svc, selectors, replicas, **kwargs):
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
    return deployment, svc
