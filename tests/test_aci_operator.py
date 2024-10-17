import os
import pytest
import subprocess
import time
import yaml

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.input.cfg import APIC_PROVISION_FILE
from tests import lib_helper
from tests import lib

LOG = logger.get_logger(__name__)
# maximum waiting time for aci resource to gets deleted.
MAX_WAITING_TIME = 300
EXEC_TIMEOUT = 180
INTERVAL = 30

ACI_CONTAINERS_LABEL = ['aci-containers-controller',
                        'aci-containers-host',
                        'aci-containers-openvswitch']
ACI_OPERATOR_POD_LABEL = 'aci-containers-operator'


pytestmark = pytest.mark.skipif(lib.is_rke1_setup() or lib.is_rke2_setup(), reason="Setup"
                                "Skipping the Test as the Setup is Rancher")

@pytest.fixture(scope="module")
def get_aci_namespace():
    """Return aci namespace."""
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision)
    aci_namespace = 'kube-system' if cluster_info.get(
        'use_kube_naming_convention') else 'aci-containers-system'
    return aci_namespace


def test_aci_operator(get_aci_namespace):
    aci_namespace = get_aci_namespace
    cr_file = _generate_cr_file(aci_namespace)
    cmd = "kubectl delete -f %s" % cr_file
    _execute(cmd.split())
    check_if_aci_resources_are_deleted(aci_namespace)
    cmd = "kubectl create -f %s" % cr_file
    _execute(cmd.split())
    check_if_aci_resources_are_up(aci_namespace)


def test_aci_operator_delete(get_aci_namespace):
    namespace = get_aci_namespace
    # delete aci containers operator pod
    _delete_pod(ACI_OPERATOR_POD_LABEL, namespace)
    max_time = time.time() + MAX_WAITING_TIME
    while True:
        output = _get_pods_details(ACI_OPERATOR_POD_LABEL, namespace)
        if len(output.get('items')) != 0:
            if output['items'][0]['status']['phase'] == "Running":
                LOG.info('pod with label [%s] '
                         'namespace [%s] is up' % (ACI_OPERATOR_POD_LABEL,
                                                   namespace))
                break
        if time.time() >= max_time:
            assert False, ('pod with label [%s] '
                'namespace [%s] is not up' % (ACI_OPERATOR_POD_LABEL,
                                              namespace))
        time.sleep(INTERVAL)


def check_if_aci_resources_are_deleted(namespace):
    max_time = time.time() + MAX_WAITING_TIME
    while True:
        count = 0
        for label in ACI_CONTAINERS_LABEL:
            output = _get_pods_details(label, namespace)
            if len(output.get('items')) == 0:
                LOG.info('pod with label [%s] '
                         'namespace [%s] is deleted' % (label, namespace))
                count += 1
        if count == len(ACI_CONTAINERS_LABEL):
            LOG.info("All ACI resources are deleted.")
            break
        if time.time() >= max_time:
            assert False, "All ACI resources are not deleted."
        time.sleep(INTERVAL)


def check_if_aci_resources_are_up(namespace):
    max_time = time.time() + MAX_WAITING_TIME
    while True:
        count = 0
        for label in ACI_CONTAINERS_LABEL:
            output = _get_pods_details(label, namespace)
            pod_count = 0
            for pod_details in output['items']:
                if pod_details['status']['phase'] == "Running":
                    pod_count += 1
                    LOG.info('pod with label [%s] '
                             'namespace [%s] is up' % (label, namespace))
            if pod_count != 0 and pod_count == len(output['items']):
                count += 1
        if count == len(ACI_CONTAINERS_LABEL):
            LOG.info("All ACI resources are up.")
            break
        if time.time() >= max_time:
            assert False, "All ACI resources are not up."
        time.sleep(INTERVAL)


def _get_pods_details(label, aci_namespace):
    kapi = KubeAPI()
    pod_label = 'name={}'.format(label)
    temp = {'labels': pod_label}
    pods_info = kapi.get_detail('pod', namespace=aci_namespace, **temp)
    return pods_info


def _delete_pod(label, aci_namespace):
    kapi = KubeAPI()
    pods_info = _get_pods_details(label, aci_namespace)
    for items in pods_info['items']:
        pod_name = items['metadata']['name']
        LOG.info("Deleting pod[%s]" % pod_name)
        kapi.delete_object('pod', pod_name,
                           namespace=aci_namespace)


def _execute(cmd):
    process_output = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    output, err = process_output.communicate(timeout=EXEC_TIMEOUT)
    if process_output.returncode != 0:
        raise Exception(err)
    output = yaml.safe_load(output)
    return output


def _generate_cr_file(aci_namespace):
    cr_file = os.getcwd() + 'cr.yaml'
    cmd = "kubectl get acicontainersoperators acicnioperator -n %s -o yaml" % aci_namespace
    output = _execute(cmd.split())
    with open(cr_file, 'w') as cust_resource_file:
        cust_resource_file.write(yaml.dump(output))
    return cr_file
