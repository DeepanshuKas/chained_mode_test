import os
import pytest
import random
import string
import time

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.input.cfg import APIC_PROVISION_FILE
from tests import lib, lib_helper
from tests.template_utils import env


LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
TIMEOUT = 500  # waiting time for pod to come up after deletions
INTERVAL = 20


@pytest.mark.parametrize('pod_label', [
    'aci-containers-controller',
    'aci-containers-openvswitch',
    'aci-containers-host'
])
def test_resilience(gen_template_name, base_fixture, pod_label):
    """Test Resilience.

    This test performs below steps.
    1)Launch pods.
    2)Check if network connection exists between pods.
    3)Delete pods having label i.e (aci-containers-controller or
      aci-containers-openvswitch or aci-containers-host)
    4)Again check if network connection exists between pods.
    5)Launch new pods.
    6)Check if network connection exists between newly launched pods.
    """
    kapi = KubeAPI()

    def _generate_unique_id(size):
        return ''.join(random.choices(string.ascii_letters + string.digits,
                                      k=size))
    pod1_name = 'pod-' + _generate_unique_id(5).lower()
    pod2_name = 'pod-' + _generate_unique_id(5).lower()

    def _generate_template(pod):
        template = env.get_template('busybox_networking.yaml')
        pod_rend_temp = template.render(pod=pod)
        pod_temp_name = gen_template_name('tpc_%s' % pod['name'])
        with open(pod_temp_name, 'w') as outfile:
            outfile.write(pod_rend_temp)
            outfile.write('\n')
        return pod_temp_name

    pod1_info = {'name': pod1_name}
    pod1_template = _generate_template(pod1_info)

    pod2_info = {'name': pod2_name}
    pod2_template = _generate_template(pod2_info)

    pod1 = lib.create_resource(pod1_template, base_fixture)
    pod2 = lib.create_resource(pod2_template, base_fixture)

    pod1_detail = kapi.get_detail('pod', name=pod1['name'],
                                  namespace="default")
    pod1_ip = pod1_detail['status']['podIP']

    pod2_detail = kapi.get_detail('pod', name=pod2['name'],
                                  namespace="default")
    pod2_ip = pod2_detail['status']['podIP']
    LOG.info("Verifying network connections between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))
    cmd1 = "-- python3 client.py  %s --timeout 30" % (pod2_ip)
    res1 = kapi.kexec(pod1['name'], cmd1, namespace="default")

    cmd2 = "-- python3 client.py  %s --timeout 30" % (pod1_ip)
    res2 = kapi.kexec(pod2['name'], cmd2, namespace="default")

    assert pod2['name'] in str(res1), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
    assert pod1['name'] in str(res2), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod2['name'], pod1['name']))
    LOG.info("Network connections exists between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision)
    aci_namespace = 'kube-system' if cluster_info.get(
        'use_kube_naming_convention') else 'aci-containers-system'

    pod_label = 'name={}'.format(pod_label)
    temp = {'labels': pod_label}
    pods_info = kapi.get_detail('pod', namespace=aci_namespace, **temp)

    pod_list = list()
    for items in pods_info['items']:
        pod_name = items['metadata']['name']
        pod_list.append(pod_name)

    if len(pod_list) == 0:
        pytest.skip("The ACI plugin is not installed on this cluster.")

    # iterate over the pod list and delete the pod
    for pod_name in pod_list:
        LOG.info("Deleting pod[%s]" % pod_name)
        kapi.delete_object('pod', pod_name,
                           namespace=aci_namespace)
        LOG.info("Deleted pod[%s]" % pod_name)

    max_time = time.time() + TIMEOUT
    while True:
        recreated_pods = 0
        pods_detail = kapi.get_detail('pod', namespace=aci_namespace, **temp)
        for items in pods_detail['items']:
            pod_name = items['metadata']['name']
            pod_status = items['status']['phase']
            if pod_status in ["Running", "Ready"]:
                recreated_pods += 1
        if recreated_pods >= len(pod_list):
            break
        if time.time() >= max_time:
            assert False
        time.sleep(INTERVAL)

    LOG.info("Verifying network connections between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))

    assert pod2['name'] in str(res1), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
    assert pod1['name'] in str(res2), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod2['name'], pod1['name']))
    LOG.info("Network connections exists between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))

    LOG.info("Verifying cluster networking after container restart.")
    verify_connectivity(gen_template_name, base_fixture)


@pytest.mark.usefixtures("clean_gen_templates")
def verify_connectivity(gen_template_name, base_fixture):
    """Launch pods and verify network connections between pods."""
    kapi = KubeAPI()

    def _generate_unique_id(size):
        return ''.join(random.choices(string.ascii_letters + string.digits,
                                      k=size))
    pod1_name = 'pod-' + _generate_unique_id(5).lower()
    pod2_name = 'pod-' + _generate_unique_id(5).lower()

    def _generate_template(pod):
        template = env.get_template('busybox_networking.yaml')
        pod_rend_temp = template.render(pod=pod)
        pod_temp_name = gen_template_name('tpc_%s' % pod['name'])
        with open(pod_temp_name, 'w') as outfile:
            outfile.write(pod_rend_temp)
            outfile.write('\n')
        return pod_temp_name

    pod1_info = {'name': pod1_name}
    pod1_template = _generate_template(pod1_info)

    pod2_info = {'name': pod2_name}
    pod2_template = _generate_template(pod2_info)

    pod1 = lib.create_resource(pod1_template, base_fixture)
    pod2 = lib.create_resource(pod2_template, base_fixture)

    pod1_detail = kapi.get_detail('pod', name=pod1['name'],
                                  namespace="default")
    pod1_ip = pod1_detail['status']['podIP']

    pod2_detail = kapi.get_detail('pod', name=pod2['name'],
                                  namespace="default")
    pod2_ip = pod2_detail['status']['podIP']
    cmd1 = "-- python3 client.py  %s --timeout 30" % (pod2_ip)
    res1 = kapi.kexec(pod1['name'], cmd1, namespace="default")

    cmd2 = "-- python3 client.py  %s --timeout 30" % (pod1_ip)
    res2 = kapi.kexec(pod2['name'], cmd2, namespace="default")

    LOG.info("Verifying network connections between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))
    assert pod2['name'] in str(res1), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
    assert pod1['name'] in str(res2), ('Network connections failed '
        'from pod [%s] to pod [%s]' % (pod2['name'], pod1['name']))
    LOG.info("Network connections exists between pod[%s] "
             "and pod[%s]" % (pod1['name'], pod2['name']))
