import os
import pytest
import subprocess
import time
import yaml

from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib, lib_helper
from tests.server_utils import ServerUtils
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD,
                             NAMESPACE_COUNT)
from tests.template_utils import env

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
SRV_UTILS = ServerUtils()
K8S_RESOURCE = ['namespace',
                'service',
                'deployment',
                'replicaset',
                'pod']
APIC_CLASSES = ['vmmInjectedNs',
                'vmmInjectedSvc',
                'vmmInjectedDepl',
                'vmmInjectedReplSet',
                'vmmInjectedContGrp']


@pytest.mark.usefixtures("clean_gen_templates")
def test_object_count(base_fixture, gen_template_name):
    """Verify kubernetes/apic object count.

    steps.
    1)Get object count of existing resources i.e(ns/svcs/depls/replset/pods)
    for kubernetes and for vmminjected objects present on APIC.
    2)Create the kubernetes resources(ns/svcs/depls/replset/pods).
    3)Scale up and scale down the resources and verify the
      respective objects counts for k8s objects and for apic objects.
      Make sure respective increase/decrease in count reflect
      on kubernetes resources and on object present on APIC.
    3)Delete the created resources and verify the objects counts.
      object count should match to object count calculated at
      the start of test.
    """
    dep_info, ns_info = [], []
    k8s_obj_count, apic_obj_count = {}, {}
    ns_list = ["apic-sub-ns-"+str(i) for i in range(NAMESPACE_COUNT)]
    # get aci client
    aci_client, vmm = get_aci_client_and_vmm()
    # store existing k8s objects and apic objects count values.
    for resource, cls_name in zip(K8S_RESOURCE, APIC_CLASSES):
        k8s_obj_count[resource] = lib.get_k8s_resource_count(resource)
        apic_obj_count[resource] = aci_client.get_mo_count(vmm, cls_name)

    LOG.info("Existing kubernetes object count details: %s" % k8s_obj_count)
    LOG.info("Existing apic object count details: %s" % apic_obj_count)

    for ns_name in ns_list:
        ns = _get_input_for_namespace(ns_name)
        ns_info.append(ns)
        select_name = ns['name'] + lib.generate_random_string(4)
        deployment_name = ns['name'] + "-dep-" + lib.generate_random_string(4)
        svc_name = ns['name'] + "-svc-" + lib.generate_random_string(4)
        selector = {'test': select_name}
        deploy_in = {'name': deployment_name, 'namespace': ns['name']}
        svc_in = {'name': svc_name, 'namespace': ns['name']}
        dep_info.append(deploy_in)
        deployment, svc = _get_input_for_svc_and_deployment(
            deploy_in, svc_in, selector)

        for rsc in [ns, deployment, svc]:
            template = env.get_template(rsc['template'])
            rend_temp = template.render(input=rsc)
            temp_name = gen_template_name(rsc['name'])
            lib_helper.dump_template(temp_name, rend_temp)
            lib.create_resource(temp_name, base_fixture)
        LOG.info("ALL the resources for ns %s are created." % ns['name'])

    scale_up_count = get_scale_up_count(NAMESPACE_COUNT)
    max_wait_time = get_max_wait_scale_up_time()
    for deploy_in, ns in zip(dep_info, ns_info):
        lib.scale_deployment(
            deploy_in['name'], scale_up_count, ns['name'],
            wait_until_scale=True,
            timeout=max_wait_time)

    for resource, cls_name in zip(K8S_RESOURCE, APIC_CLASSES):
        k8s_expected_count = k8s_obj_count.get(resource) + NAMESPACE_COUNT
        apic_expected_count = apic_obj_count.get(resource) + NAMESPACE_COUNT
        if resource == 'pod':
            count = scale_up_count * NAMESPACE_COUNT
            k8s_expected_count = k8s_obj_count.get(resource) + count
            apic_expected_count = apic_obj_count.get(resource) + count
        check_expected_k8s_obj_count(resource, k8s_expected_count)
        check_expected_apic_obj_count(aci_client, vmm,
                                      cls_name, apic_expected_count)

    scale_down_replica_count = int(scale_up_count / 2)
    delete_wait_time = int(max_wait_time / 2)
    for deploy_in, ns in zip(dep_info, ns_info):
        lib.scale_deployment(
            deploy_in['name'], scale_down_replica_count, ns['name'],
            wait_until_scale=True,
            timeout=max_wait_time)

    LOG.info("Waiting for Reconciliation time period "
             "of %s Second" % delete_wait_time)
    time.sleep(delete_wait_time)
    LOG.info("Verifying object count values after resources scale down")

    for resource, cls_name in zip(K8S_RESOURCE, APIC_CLASSES):
        k8s_expected_count = k8s_obj_count.get(resource) + NAMESPACE_COUNT
        apic_expected_count = apic_obj_count.get(resource) + NAMESPACE_COUNT
        if resource == 'pod':
            count = scale_down_replica_count * NAMESPACE_COUNT
            k8s_expected_count = k8s_obj_count.get(resource) + count
            apic_expected_count = apic_obj_count.get(resource) + count
        check_expected_k8s_obj_count(resource, k8s_expected_count)
        check_expected_apic_obj_count(aci_client, vmm,
                                      cls_name, apic_expected_count)

    delete_ns(ns_info, delete_wait_time)
    LOG.info("Verifying object count values after resource deletion")
    for resource, cls_name in zip(K8S_RESOURCE, APIC_CLASSES):
        k8s_expected_count = k8s_obj_count.get(resource)
        apic_expected_count = apic_obj_count.get(resource)
        check_expected_k8s_obj_count(resource, k8s_expected_count)
        check_expected_apic_obj_count(aci_client, vmm,
                                      cls_name, apic_expected_count)


def get_scale_up_count(ns_count):
    worker_node_count = get_worker_node_count()
    scale_count = 30 * worker_node_count / ns_count
    assert int(scale_count) >= worker_node_count, (
        "Reduce input namespace count or scale the worker nodes")
    return int(scale_count)


def get_worker_node_count():
    res = list()
    node_info = SRV_UTILS.load_nodes_information()
    for node in (node_info.get('worker_nodes', [])):
        res.append(node['hostname'])
    return len(res)


def get_max_wait_scale_up_time():
    max_time = get_scale_up_count(NAMESPACE_COUNT) * NAMESPACE_COUNT * 3
    return int(max_time)


def get_aci_client_and_vmm():
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    assert apic_provision['aci_config']['apic_hosts'], (
        "No APIC hosts specified in provision file - %s" %
        APIC_PROVISION_FILE)
    vmm = apic_provision['aci_config']['system_id']
    aci_client = lib_helper.APIC(
        user=APIC_USERNAME,
        passwd=APIC_PASSWORD,
        apic_ip=apic_provision['aci_config']['apic_hosts'][0])
    return aci_client, vmm


def check_expected_k8s_obj_count(resource, expected_count):
    obj_count = lib.get_k8s_resource_count(resource)
    LOG.info("Expected count:%s, Current count:%s, ResourceType:%s" % (
        expected_count, obj_count, resource))
    assert obj_count == expected_count, (
        "kubernetes object count for %s resource does not match" % resource)


def check_expected_apic_obj_count(aci_client, vmm, cls_name, expected_count):
    obj_count = aci_client.get_mo_count(vmm, cls_name)
    LOG.info("Expected count:%s, Current count:%s, ResourceType:%s" % (
        expected_count, obj_count, cls_name))
    assert obj_count == expected_count, (
        "apic object count for %s class does not match" % cls_name)


def delete_ns(ns_info, timeout):
    kube_client = get_kube_client()
    for ns in ns_info:
        LOG.info("Deleting Namespace:%s" % ns['name'])
        cmd = '%s delete ns %s' % (kube_client, ns['name'])
        _execute(cmd.split(), timeout)
        LOG.info("Deleted Namespace:%s" % ns['name'])
    time.sleep(120)


def _execute(cmd, timeout):
    process_output = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    output, err = process_output.communicate(timeout=timeout)
    if process_output.returncode != 0:
        raise Exception(err)
    output = yaml.safe_load(output)
    return output


def _get_input_for_svc_and_deployment(deploy, svc, selectors, **kwargs):
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
    return deployment, svc


def _get_input_for_daemonset(name, selectors, **kwargs):
    return {
        'name': name,
        'template': 'nginx_ds.yaml',
        'kind': 'daemonset',
        'selector': selectors if selectors else None
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
