import os
import pytest
import random
import string

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import aci
from tests import lib
from tests import lib_helper
from tests.template_utils import env
from tests.test_chained_mode import check_chained_mode
from tests.input.cfg import (ACI_PREFIX,
                             APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD,
                             APIC_VALIDATION)

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
pytestmark = pytest.mark.skipif(check_chained_mode() is True, reason="Setup : "
                                "Not applicable for chained mode")
pytestmark = pytest.mark.skipif(APIC_VALIDATION is False, reason="apic "
                                "validation flag is disabled.")


@pytest.fixture(scope="module")
def get_clusters_info():
    kapi = KubeAPI()
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(
          apic_provision)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    apic = aci.APIC(apic_host, APIC_USERNAME, APIC_PASSWORD)
    return kapi, apic, cluster_info


@pytest.mark.usefixtures("clean_gen_templates")
def test_same_epg_same_uplink(base_fixture, gen_template_name, get_clusters_info):
    """Test same epg same uplink.

    This test performs below steps.
    1)Create epg.
    2)Launch pods in epg.
    4)Tests if a network connection exists between pods.
    """
    kapi, apic, cluster_info = get_clusters_info
    tenant_name = cluster_info['tenant']
    appprofile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']

    def _generate_unique_id(size):
        return ''.join(random.choices(string.ascii_letters + string.digits,
                                      k=size))

    epg_1 = 'remote-epg-' + _generate_unique_id(6)
    pod1_name = 'pod-' + _generate_unique_id(6).lower()
    pod2_name = 'pod-' + _generate_unique_id(6).lower()

    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'
    epg1 = apic.clone_kubernetes_epg(epg_1, tenant_name,
                                     cluster_info['system_id'],
                                     source_epg_name=source_epg_name,
                                     app_profile=appprofile,
                                     kube_naming_used=kube_naming_used)

    def _generate_template(pod):
        template = env.get_template('busybox_networking.yaml')
        annot = '{"app-profile": "%s", "name": "%s","tenant": "%s"}' % (
            pod['appprofile'], pod['epg'], tenant_name)
        pod.update({'annotations': annot})
        pod_rend_temp = template.render(pod=pod)
        pod_temp_name = gen_template_name('tpc_%s' % pod['name'])
        with open(pod_temp_name, 'w') as outfile:
            outfile.write(pod_rend_temp)
            outfile.write('\n')
        return pod_temp_name

    pod1_info = {'name': pod1_name, 'epg': epg_1, 'appprofile': appprofile}
    pod1_template = _generate_template(pod1_info)

    pod2_info = {'name': pod2_name, 'epg': epg_1, 'appprofile': appprofile}
    pod2_template = _generate_template(pod2_info)
    pod1, pod2 = None, None
    try:
        pod1 = lib.create_resource(pod1_template, base_fixture)
        pod2 = lib.create_resource(pod2_template, base_fixture)
        pod1_detail = kapi.get_detail('pod', name=pod1['name'],
                                      namespace="default")
        pod1_ip = pod1_detail['status']['podIP']
        pod2_detail = kapi.get_detail('pod', name=pod2['name'],
                                  namespace="default")
        pod2_ip = pod2_detail['status']['podIP']
        cmd1 = "-- python3 client.py  %s --timeout 30" % (pod2_ip)
        cmd2 = "-- python3 client.py  %s --timeout 30" % (pod1_ip)
        res1 = kapi.kexec(pod1['name'], cmd1, namespace="default")
        res2 = kapi.kexec(pod2['name'], cmd2, namespace="default")
        assert pod2['name'] in str(res1), ('Network connections failed '
            'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
        assert pod1['name'] in str(res2), ('Network connections failed '
            'from pod [%s] to pod [%s]' % (pod2['name'], pod1['name']))
    finally:
        if pod1:
            kapi.delete_object('pod', pod1['name'],
                               namespace=pod1['namespace'])
        if pod2:
            kapi.delete_object('pod', pod2['name'],
                               namespace=pod2['namespace'])
        apic.delete_epg(epg1)


@pytest.mark.usefixtures("clean_gen_templates")
def test_diff_epg_same_uplink(base_fixture, gen_template_name, get_clusters_info):
    """Test different epg same uplink.

    This test performs below steps.
    1)Create 2 epgs.
    2)Launch pod in each epgs.
    3)Create a contract to allow tcp traffic on 5001 port.
    4)Tests if a network connection exists between pods.
    """
    kapi, apic, cluster_info = get_clusters_info
    tenant_name = cluster_info['tenant']
    appprofile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']

    def _generate_unique_id(size):
        return ''.join(random.choices(string.ascii_letters + string.digits,
                                      k=size))

    epg_1 = 'remote-epg-' + _generate_unique_id(6)
    epg_2 = 'remote-epg-' + _generate_unique_id(6)
    pod1_name = 'pod-' + _generate_unique_id(6).lower()
    pod2_name = 'pod-' + _generate_unique_id(6).lower()
    c_name = 'contract-' + _generate_unique_id(6)
    filt_entry = 'filt-entry-' + _generate_unique_id(6)

    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'

    epg1 = apic.clone_kubernetes_epg(epg_1, tenant_name,
                                     cluster_info['system_id'],
                                     app_profile=appprofile,
                                     source_epg_name=source_epg_name,
                                     kube_naming_used=kube_naming_used)
    epg2 = apic.clone_kubernetes_epg(epg_2, tenant_name,
                                     cluster_info['system_id'],
                                     source_epg_name=source_epg_name,
                                     app_profile=appprofile,
                                     kube_naming_used=kube_naming_used)

    kube_tenant = apic.get_tenant(tenant_name)
    contract = apic.create_contract(c_name, kube_tenant)
    entry1 = apic.create_filter_entry(filt_entry, contract,
                                      kube_tenant, dFromPort='5001', dToPort='5001')

    apic.provide(epg2, contract)
    apic.consume(epg1, contract)

    def _generate_template(pod):
        template = env.get_template('busybox_networking.yaml')
        annot = '{"app-profile": "%s", "name": "%s","tenant": "%s"}' % (
            pod['appprofile'], pod['epg'], tenant_name)
        pod.update({'annotations': annot})
        pod_rend_temp = template.render(pod=pod)
        pod_temp_name = gen_template_name('tpc_%s' % pod['name'])
        with open(pod_temp_name, 'w') as outfile:
            outfile.write(pod_rend_temp)
            outfile.write('\n')
        return pod_temp_name

    pod1_info = {'name': pod1_name, 'epg': epg_1, 'appprofile': appprofile}
    pod1_template = _generate_template(pod1_info)

    pod2_info = {'name': pod2_name, 'epg': epg_2, 'appprofile': appprofile}
    pod2_template = _generate_template(pod2_info)
    pod1, pod2 = None, None

    try:
        pod1 = lib.create_resource(pod1_template, base_fixture)
        pod2 = lib.create_resource(pod2_template, base_fixture)

        pod2_detail = kapi.get_detail('pod', name=pod2['name'],
                                      namespace="default")
        pod2_ip = pod2_detail['status']['podIP']
        cmd1 = "-- python3 client.py  %s  --port %s  --timeout 30" % (pod2_ip,
                                                                      "5001")
        cmd2 = "-- python3 client.py  %s --timeout 30" % (pod2_ip)
        res1 = kapi.kexec(pod1['name'], cmd1, namespace="default")
        res2 = kapi.kexec(pod1['name'], cmd2, namespace="default")
        assert pod2['name'] in str(res1), ('Network connections failed '
            'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
        assert "timed out" in str(res2)
    finally:
        if pod1:
            kapi.delete_object('pod', pod1['name'],
                               namespace=pod1['namespace'])

        if pod2:
            kapi.delete_object('pod', pod2['name'],
                               namespace=pod2['namespace'])
        apic.dont_consume(epg1, contract)
        apic.dont_provide(epg2, contract)
        apic.delete_contract(contract)
        apic.delete_filter_entry(entry1)
        apic.delete_filter(filt_entry + "_Filter", kube_tenant)
        apic.delete_epg(epg2)
        apic.delete_epg(epg1)


@pytest.mark.usefixtures("clean_gen_templates")
def test_diff_epg_diff_uplink(base_fixture, gen_template_name, get_clusters_info):
    """Test different epg different uplink.

    This test performs below steps.
    1)Create 2 epgs.
    2)Launch pod in each epgs.
    3)Create a contract to allow tcp traffic on any port.
    4)Tests if a network connection exists between pods.
    """
    kapi, apic, cluster_info = get_clusters_info
    tenant_name = cluster_info['tenant']
    appprofile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']

    def _generate_unique_id(size):
        return ''.join(random.choices(string.ascii_letters + string.digits,
                                      k=size))

    epg_1 = 'remote-epg-' + _generate_unique_id(6)
    epg_2 = 'remote-epg-' + _generate_unique_id(6)
    pod1_name = 'pod-' + _generate_unique_id(6).lower()
    pod2_name = 'pod-' + _generate_unique_id(6).lower()
    c_name = 'contract-' + _generate_unique_id(6)
    filt_entry = 'filt-entry-' + _generate_unique_id(6)

    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'

    epg1 = apic.clone_kubernetes_epg(epg_1, tenant_name,
                                     cluster_info['system_id'],
                                     source_epg_name=source_epg_name,
                                     app_profile=appprofile,
                                     kube_naming_used=kube_naming_used)
    epg2 = apic.clone_kubernetes_epg(epg_2, tenant_name,
                                     cluster_info['system_id'],
                                     source_epg_name=source_epg_name,
                                     app_profile=appprofile,
                                     kube_naming_used=kube_naming_used)

    kube_tenant = apic.get_tenant(tenant_name)
    contract = apic.create_contract(c_name, kube_tenant)
    entry1 = apic.create_filter_entry(filt_entry, contract, kube_tenant)
    apic.provide(epg1, contract)
    apic.consume(epg2, contract)

    def _generate_template(pod):
        template = env.get_template('busybox_networking.yaml')
        annot = '{"app-profile": "%s", "name": "%s", "tenant": "%s"}' % (
            pod['appprofile'], pod['epg'], tenant_name)
        pod.update({'annotations': annot})
        pod_rend_temp = template.render(pod=pod)
        pod_temp_name = gen_template_name('tpc_%s' % pod['name'])
        with open(pod_temp_name, 'w') as outfile:
            outfile.write(pod_rend_temp)
            outfile.write('\n')
        return pod_temp_name

    pod1_info = {'name': pod1_name, 'epg': epg_1, 'appprofile': appprofile}
    pod1_template = _generate_template(pod1_info)

    pod2_info = {'name': pod2_name, 'epg': epg_2, 'appprofile': appprofile}
    pod2_template = _generate_template(pod2_info)
    pod1, pod2 = None, None
    try:
        pod1 = lib.create_resource(pod1_template, base_fixture)
        pod2 = lib.create_resource(pod2_template, base_fixture)
        pod2_detail = kapi.get_detail('pod', name=pod2['name'],
                                      namespace="default")
        pod1_detail = kapi.get_detail('pod', name=pod1['name'],
                                      namespace="default")
        pod2_ip = pod2_detail['status']['podIP']
        pod1_ip = pod1_detail['status']['podIP']
        cmd1 = "-- python3 client.py  %s  --timeout 30" % (pod2_ip)
        cmd2 = "-- python3 client.py  %s  --timeout 30" % (pod1_ip)
        res1 = kapi.kexec(pod1['name'], cmd1, namespace="default")
        res2 = kapi.kexec(pod2['name'], cmd2, namespace="default")
        assert pod2['name'] in str(res1), ('Network connections failed '
            'from pod [%s] to pod [%s]' % (pod1['name'], pod2['name']))
        assert pod1['name'] in str(res2), ('Network connections failed '
            'from pod [%s] to pod [%s]' % (pod2['name'], pod1['name']))
    finally:
        if pod1:
            kapi.delete_object('pod', pod1['name'],
                               namespace=pod1['namespace'])
        if pod2:
            kapi.delete_object('pod', pod2['name'],
                           namespace=pod2['namespace'])
        apic.dont_consume(epg1, contract)
        apic.dont_provide(epg2, contract)
        apic.delete_filter_entry(entry1)
        apic.delete_filter(filt_entry + "_Filter", kube_tenant)
        apic.delete_contract(contract)
        apic.delete_epg(epg2)
        apic.delete_epg(epg1)
