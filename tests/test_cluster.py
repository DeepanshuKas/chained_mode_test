import pytest
import subprocess
import time

from acc_pyutils import logger
from acc_pyutils.utils import retry
from tests import lib, lib_helper
from tests.input import cfg
from tests.test_chained_mode import check_chained_mode

LOG = logger.get_logger(__name__)


# TODO(vk): Add verification for physical links.


def test_apic_reachability():
    if cfg.APIC_PROVISION_FILE:
        apic_prov = lib_helper.get_apic_provision_input(
            cfg.APIC_PROVISION_FILE)
        for host in apic_prov['aci_config']['apic_hosts']:
            assert lib_helper.is_apic_reachable(host) is True


def test_check_aci_namespaces():
    namespaces = lib.get_all_namespaces()
    assert lib.check_aci_related_namespace_exists(namespaces) is True


@pytest.mark.smoke
@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode")
def test_check_aci_pods_exists():
    pods = lib.get_all_pods(cfg.CRD_NAMESPACE)
    if pods['items']:
        aci_pods = lib.check_aci_pods(pods)
    else:
        kube_sys_pods = lib.get_all_pods(cfg.KUBE_SYSTEM)
        aci_pods = lib.check_aci_pods(kube_sys_pods)
    lib.verify_aci_pods_on_all_nodes(aci_pods)


@retry(no_of_retry=20, delay=30)
def test_aci_pods_running():
    pods = lib.get_all_pods(cfg.CRD_NAMESPACE)
    if not pods['items']:
        pods = lib.get_all_pods(cfg.KUBE_SYSTEM)
    running, aci_pods = verify_aci_pods_running(pods)
    if not running:
        assert len(aci_pods) > 0, "ACI pods not found."
        raise Exception("All ACI pods are not in running state")


def test_apic_configuration():
    apic_provision = lib_helper.get_apic_provision_input(
        cfg.APIC_PROVISION_FILE)
    assert apic_provision['aci_config']['apic_hosts'], (
        "No APIC hosts specified in provision file - %s" %
        cfg.APIC_PROVISION_FILE)
    for host in apic_provision['aci_config']['apic_hosts']:
        assert lib_helper.is_apic_reachable(host) is True
    aci_client = lib_helper.APIC(
        user=cfg.APIC_USERNAME,
        passwd=cfg.APIC_PASSWORD,
        apic_ip=apic_provision['aci_config']['apic_hosts'][0])
    verify_tenant(aci_client, apic_provision['aci_config']['system_id'])
    verify_vrf(aci_client, apic_provision['aci_config']['vrf']['name'],
               apic_provision['aci_config']['vrf']['tenant'])
    verify_l3out(aci_client, apic_provision['aci_config']['l3out']['name'],
                 apic_provision['aci_config']['vrf']['tenant'])
    verify_l3out_epg(aci_client,
                     apic_provision['aci_config']['l3out']['name'],
                     apic_provision['aci_config']['l3out'][
                         'external_networks'][0],
                     apic_provision['aci_config']['vrf']['tenant'])
    verify_kubernetes_ap(aci_client, apic_provision['aci_config']['system_id'])
    verify_kube_epgs(aci_client, apic_provision['aci_config']['system_id'])
    verify_tenant_bds(aci_client, apic_provision['aci_config']['system_id'],
                      apic_provision['net_config']['node_subnet'],
                      apic_provision['net_config']['pod_subnet'])
    verify_vmm_domain(aci_client, apic_provision['aci_config']['system_id'])
    verify_vmm_domain_configuration(aci_client,
                                    apic_provision['aci_config']['system_id'],
                                    apic_provision['aci_config'][
                                        'vmm_domain']['encap_type'])


def verify_tenant(client, tenant_name):
    aci_tenant = client.get_tenant(tenant_name)
    assert aci_tenant is not None, ("Specified tenant - %s does not exists "
                                    "in APIC " % tenant_name)
    LOG.info("Tenant - %s verified " % aci_tenant.name)


def verify_vrf(client, vrf_name, tenant_name):
    vrf = client.get_vrf(vrf_name, tenant_name)
    assert vrf is not None, ("VRF - %s does not exists in APIC for tenant "
                             "-%s" % (vrf_name, tenant_name))
    LOG.info("VRF - %s verified in %s tenant" % (vrf.name, tenant_name))


def verify_l3out(client, l3out_name, tenant_name):
    l3out = client.get_l3out(l3out_name, tenant_name)
    assert l3out is not None, ("L3out - %s does not exists in APIC for "
                               "tenant - %s" % (l3out_name, tenant_name))
    LOG.info("L3out - %s verified in %s tenant" % (l3out_name, tenant_name))


def verify_l3out_epg(client, l3out_name, epg_name, tenant_name):
    l3out_epg = client.get_l3out_epg(
        l3out_name, tenant_name, epg_name)
    assert l3out_epg is not None, ("EPG - %s does not exists in L3out - %s"
                                   % (epg_name, l3out_name))
    LOG.info("L3out EPG - %s verified in %s tenant" %
             (l3out_epg.name, tenant_name))


def verify_kubernetes_ap(client, tenant_name):
    ap = client.get_ap(tenant_name, 'kubernetes')
    assert ap is not None, ("kubernetes application profile does not exists "
                            "for tenant - %s" % tenant_name)
    LOG.info("Application Profile - %s verified in %s tenant" % (
        ap.name, tenant_name))


def verify_kube_epgs(client, tenant_name):
    ap = client.get_ap(tenant_name, 'kubernetes')
    assert ap is not None, ("kubernetes application profile does not exists "
                            "for tenant - %s" % tenant_name)
    for _epg in ['kube-nodes', 'kube-system', 'kube-default']:
        epg = client.get_epg(tenant_name, ap.name, _epg)
        assert epg is not None, ("%s epg does not exists in APIC for"
                                 " tenant - %s" % (epg.name, tenant_name))
        LOG.info("EPG - %s verified in %s tenant" % (epg.name, tenant_name))


def verify_tenant_bds(client, tenant_name, node_subnet, pod_subnet):
    tenant_bds = client.get_bds(tenant_name)
    for bd in tenant_bds:
        bd_detail = client.get_bd_detail(tenant_name, bd.name)
        LOG.info("BD - %s has theses subnets - %s" % (
            bd.name, bd_detail['subnets_addr_list']))
        assert (node_subnet in bd_detail['subnets_addr_list'] or
                pod_subnet in bd_detail['subnets_addr_list']) is True
        LOG.info("BD - %s verified in %s tenant" % (bd.name, tenant_name))


def verify_vmm_domain(client, tenant_name):
    tenant_domain = client.get_vmm_domain(tenant_name)
    assert tenant_domain['imdata'] is not None, (
        "VMM Domain does not exists for tenant - %s" % tenant_name)
    LOG.info("VMM domain verified for tenant - %s" % (tenant_name))


def verify_vmm_domain_configuration(client, tenant_name, encap_type):
    tenant_domain = client.get_vmm_domain(tenant_name)
    vmm_dom_info = _get_vmmdomain_info(tenant_domain, tenant_name)
    assert vmm_dom_info is not None, ("VMM domain  - %s info is empty" %
                                      tenant_domain.name)
    assert vmm_dom_info['name'] == tenant_name
    assert vmm_dom_info['encapMode'] == encap_type
    LOG.info("Encap Type - %s is configured in VMM domain %s" % (
        vmm_dom_info['encapMode'], vmm_dom_info['name']))
    # assert vmm_dom_info['annotation'] == (
    #     'orchestrator:aci-containers-controller')
    # LOG.info("Annotation - %s configured in VMM domain - %s" % (
    #     vmm_dom_info['annotation'], vmm_dom_info['name']))
    LOG.info("Fabric wide Multi cast address is - %s "
             % vmm_dom_info['mcastAddr'])


def verify_aci_pods_running(pods):
    failed_pods, aci_pods = list(), list()
    for _pod in pods['items']:
        if 'aci' in _pod['metadata']['name']:
            try:
                for container_status in _pod['status']['containerStatuses']:
                    if not container_status['ready'] or "running" not in \
                            container_status['state']:
                        # LOG.error("Pod - %s not running" %
                        #           _pod['metadata']['name'])
                        failed_pods.append(False)
            except KeyError:
                raise Exception('Pod - %s has some issues. %s' %
                                (_pod['metadata']['name'], _pod))
            aci_pods.append(_pod['metadata']['name'])
    if not all(failed_pods):
        # REVISIT(VK): This has environment issue.
        # subprocess.run(
        #     ["bash", "-c", "kubectl get pods --all-namespaces | grep aci"])
        LOG.error("Pods %s are not running. " % aci_pods)
    return all(failed_pods), aci_pods


def _get_vmmdomain_info(tenant_domain, tenant_name):
    for domp in tenant_domain['imdata']:
        if domp['vmmDomP']['attributes']['name'] == tenant_name:
            vmm_dom_info = {
                k: v for k, v in domp['vmmDomP']['attributes'].items()
                if k in ['name', 'encapMode', 'prefEncapMode', 'mcastAddr',
                         'annotation']
                }
            return vmm_dom_info
