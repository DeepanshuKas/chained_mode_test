import os
import pytest

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import aci
from tests import lib
from tests import lib_helper
from tests.template_utils import env
from acc_pyutils.exceptions import KctlExecutionFailed
from tests.input.cfg import (ACI_PREFIX,
                             APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
BB_TEMPLATE = env.get_template('alpine.yaml')


@pytest.fixture(scope="module")
def get_clusters_info():
    kapi = KubeAPI()
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = \
        lib_helper.get_resource_details_from_acc_provision_input_file(
            apic_provision)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, APIC_USERNAME, APIC_PASSWORD)
    return kapi, apic, cluster_info


@pytest.mark.usefixtures("clean_gen_templates")
def test_droplog(base_fixture, gen_template_name, get_clusters_info):
    """Test droplog.

    This test performs below steps.
    1)Create two pods on same node.
    2)Create a separate EPG with no contracts.
      Annotate one of the pods to move to this EPG.
    3)Verify ping traffic between pods, Ping will fail.
    4)Verify below event on source pod.
       Warning  Int-POL_TABLE MISS(Policy Drop)  103s   aci-containers-host
       IPv4 packet from default/test-droplog-source-pod to
       default/test-droplog-target-pod was dropped
    """
    kapi, apic, cluster_info = get_clusters_info
    tenant_name = cluster_info['tenant']
    appprofile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']
    pods = dict()

    node = lib.get_worker_nodes_hostname()[0]
    source_pod = _create_bb_pod(
        base_fixture, gen_template_name,
        _get_input('test-droplog-source-pod', node_name=node,
                   labels={'test': 'droplog'}), BB_TEMPLATE)
    pods['test-droplog-source-pod'] = source_pod
    epg_name = "epg-" + lib.generate_random_string(6)
    source_epg_name = _get_source_epg(kube_naming_used)
    epg1 = apic.clone_kubernetes_epg(epg_name, tenant_name,
                                     cluster_info['system_id'],
                                     source_epg_name=source_epg_name,
                                     app_profile=appprofile,
                                     kube_naming_used=kube_naming_used,
                                     contract=False)
    try:
        target_pod = None
        annot = '{"app-profile": "%s", "name": "%s","tenant": "%s"}' % (
                appprofile, epg_name, tenant_name)
        target_pod = _create_bb_pod(base_fixture, gen_template_name,
                                    _get_input('test-droplog-target-pod',
                                               node_name=node,
                                               annotations=annot,
                                               labels={'test': 'droplog'}),
                                    BB_TEMPLATE)
        pods['test-droplog-target-pod'] = target_pod

        p1_name, p2_name = ("test-droplog-source-pod", "test-droplog-target-pod")
        LOG.info("Testing ping between pods %s %s" % (p1_name, p2_name))
        for p_name in [p1_name, p2_name]:
            dst_pod = list({p1_name, p2_name} - {p_name})[0]
            tip = lib_helper.get_pod_ip(
                dst_pod, pods[dst_pod]['namespace'])
            _check_ping_from_pod(
                 p_name, pods[p_name]['namespace'], tip,
                 target='pod')

        pa_details = kapi.describe('pod', p1_name, namespace="default")
        assert ("Int-POL_TABLE MISS(Policy Drop)" in pa_details.decode())
        assert ("packet from default/%s to default/%s was dropped "
                "in %s" % (p1_name, p2_name, pa_details.decode()))
    finally:
        if target_pod:
            kapi.delete_object('pod', p2_name,
                               namespace="default")
        apic.delete_epg(epg1)
        LOG.info('Deleted  EPG %s from TENANT %s', epg_name, tenant_name)


def _get_input(name, generate_name=None, annotations=None,
               labels=None, node_name=None, namespace=None):
    arguments = locals()
    return {k: arguments[k] for k in list(arguments.keys()) if arguments[k]
            is not None}


def _create_bb_pod(base_fixture, gen_template_name, pod_input, pod_template):
    rend_temp = pod_template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    return lib.create_resource(temp_name, base_fixture)


def _get_source_epg(kube_naming_used):
    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'
    return source_epg_name


def _check_ping_from_pod(pod, namespace, target_ip, **kwargs):
    kapi = KubeAPI()
    try:
        kapi.kexec(pod,
                   'ping -c5 %s' % target_ip,
                   namespace=namespace,
                   interpreter='sh -c')
    except KctlExecutionFailed as ex:
        LOG.info("Pod - %s failed to ping - %s . - %s" % (
            pod, target_ip, ex.message))
