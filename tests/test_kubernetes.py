import os
import pytest
import time
import pytest
import yaml

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.input.cfg import (APIC_PROVISION_FILE,
                             ACI_PREFIX,
                             APIC_USERNAME,
                             APIC_PASSWORD,
                             APIC_VALIDATION)

from tests import aci, lib, lib_helper
from tests.input.cfg import ENDPOINT_WAIT_TIME
from tests.test_chained_mode import check_chained_mode

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
# kubernetes cluster's application profile name
APP_NAME = "kubernetes"
# kubernetes default epg.
DEFAULT_EPG = "kube-default"
INTERVAL = 15
NAMESPACE = 'kubernetes-test'


@pytest.mark.smoke
def test_pod_status(base_fixture):
    """launch pod and verify it's status."""
    kapi = KubeAPI()

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_test.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    # get pod details
    pod_info = kapi.get('pod', pod['name'], namespace=NAMESPACE)
    # verify pod status
    assert pod_info.get('phase') == "Running", (
        "pod[%s] is not in Running state." % pod['name'])


def test_pod_ip(base_fixture):
    """launch pod and verify it's ip."""
    kapi = KubeAPI()

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_test.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    # get pod details
    pod_info = kapi.get('pod', pod['name'], namespace=NAMESPACE)

    # verify pod's ip
    assert pod_info.get('podIP'), (
        "IP Address not found for pod [%s]" % pod['name'])


def test_pod_exec(base_fixture):
    """launch pod and verify pod exec."""
    kapi = KubeAPI()

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_test.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    res = kapi.kexec(pod['name'], "hostname", namespace=NAMESPACE)
    assert pod['name'] in str(res)


def test_pod_logs(base_fixture):
    """launch pod and get pod logs."""
    kapi = KubeAPI()

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_test.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    pod_logs = kapi.logs(pod['name'], namespace=NAMESPACE)
    assert str(pod_logs)


@pytest.mark.smoke
def test_non_root_pod(base_fixture):
    """Verify pod with securityContext defining limited permissions(non root)."""
    kapi = KubeAPI()

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_non_root.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    # get pod details
    pod_info = kapi.get('pod', pod['name'], namespace=NAMESPACE)

    # verify pod status
    assert pod_info.get('phase') == "Running", (
        "pod[%s] is not in Running state." % pod['name'])

@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode")
@pytest.mark.skipif(APIC_VALIDATION is False, reason="apic validation "
                    "flage is disabled.")
def test_epg_endpoint(base_fixture):
    """Verify that Pod is learned in EPG in ACI."""
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, APIC_USERNAME, APIC_PASSWORD)

    ns_input = lib.get_input_for_namespace(NAMESPACE)
    lib.create_resource_from_template(ns_input, base_fixture)

    pod_manifest_path = '{}/busybox_test.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = NAMESPACE
    lib_helper.dump_template(pod_manifest['metadata']['name'], str(pod_manifest))
    pod = lib.create_resource(pod_manifest['metadata']['name'], base_fixture)

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision)
    KUBE_DEFAULT_EPG = 'kube-default'
    if not cluster_info['use_kube_naming_convention']:
        KUBE_DEFAULT_EPG = ACI_PREFIX + '-default'
    max_time = time.time() + ENDPOINT_WAIT_TIME
    # verify pod's learning source
    # until it timeouts, expected learning source is "learned,vmm"
    while True:
        pod_epg_endpoints = apic.get_endpoints(cluster_info['tenant'],
                                               cluster_info['app_profile'],
                                               KUBE_DEFAULT_EPG, pod['name'])
        if pod_epg_endpoints:
            if pod_epg_endpoints.lcC == 'learned,vmm':
                LOG.info("pod [%s] learning source is"
                         " learned,vmm" % pod['name'])
                break
        if time.time() >= max_time:
            assert False, "pod[%s] is not learned in aci" % pod['name']
        time.sleep(INTERVAL)


def test_deployment_service_in_namespace(base_fixture):
    kapi = KubeAPI()

    namespace = lib.create_resource(
        '{}/test_namespace.yaml'.format(DATA_DIR), base_fixture)

    deployment = lib.create_resource(
        '{}/test_nginx_deployment.yaml'.format(DATA_DIR), base_fixture)

    svc = lib.create_resource('{}/test_nginx_service.yaml'.format(DATA_DIR),
                              base_fixture)

    base_fixture['delete_info'].reverse()

    # get deployment info
    dep_info = kapi.get_detail('deployment', name=deployment['name'],
                               namespace=namespace['name'])

    assert dep_info['metadata']['name'] == deployment['name']

    # get service info
    service_info = kapi.get_detail('service', name=svc['name'],
                                   namespace=namespace['name'])

    assert service_info['metadata']['name'] == svc['name']

    # get deployment spec template matadata label
    dep_template_label = dep_info['spec']['template']['metadata']['labels']['app']
    # get deployment selector match label
    dep_selector_label = dep_info['spec']['selector']['matchLabels']['app']
    # get service selector label
    service_spec_selector_label = service_info['spec']['selector']['app']

    # match labels
    assert dep_template_label == dep_selector_label
    assert dep_template_label == service_spec_selector_label
