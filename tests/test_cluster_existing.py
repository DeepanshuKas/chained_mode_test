import pytest

from acc_pyutils import logger
from tests.input import cfg
from tests import lib
from tests import lib_helper
from tests.test_chained_mode import check_chained_mode
from tests.vm_migration_helper import get_apic_aci


LOG = logger.get_logger(__name__)


@pytest.mark.smoke
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


@pytest.mark.smoke
def test_apic_configuration():
    apic_provision = lib_helper.get_apic_provision_input(
        cfg.APIC_PROVISION_FILE)
    assert apic_provision['aci_config']['apic_hosts'], (
        "No APIC hosts specified in provision file - %s" %
        cfg.APIC_PROVISION_FILE)
    for host in apic_provision['aci_config']['apic_hosts']:
        assert lib_helper.is_apic_reachable(host) is True
    apic_aci_client = get_apic_aci()

    # check if cluster is configured under preexisting tenant
    aci_config = apic_provision['aci_config']
    use_kube_naming_convention = False
    if 'tenant' in aci_config:
        tenant = aci_config['tenant']['name']
        assert tenant, ("Tenant name is not configured "
                        "in %s" % cfg.APIC_PROVISION_FILE)
    else:
        tenant = aci_config['system_id']
    if apic_provision.get('chained_cni_config', {}).get('primary_interface_chaining') or (
        apic_provision.get('chained_cni_config', {}).get('secondary_interface_chaining')):
        app_profile = cfg.ACI_CHAINED_PREFIX  + '-' + aci_config['system_id']
    elif 'use_legacy_kube_naming_convention' in aci_config:
        if aci_config['use_legacy_kube_naming_convention']:
            app_profile = 'kubernetes'
            use_kube_naming_convention = True
        else:
            app_profile = cfg.ACI_PREFIX + '-' + aci_config['system_id']
    else:
        app_profile = cfg.ACI_PREFIX + '-' + aci_config['system_id']

    verify_tenant(apic_aci_client, tenant)
    verify_vrf(apic_aci_client, apic_provision['aci_config']['vrf']['name'],
               apic_provision['aci_config']['vrf']['tenant'])
    verify_l3out(apic_aci_client, apic_provision['aci_config']['l3out']['name'],
                 apic_provision['aci_config']['vrf']['tenant'])
    verify_l3out_epg(apic_aci_client,
                     apic_provision['aci_config']['l3out']['name'],
                     apic_provision['aci_config']['l3out'][
                         'external_networks'][0],
                     apic_provision['aci_config']['vrf']['tenant'])
    verify_kubernetes_ap(apic_aci_client, tenant, app_profile)
    verify_kube_epgs(apic_aci_client, tenant, app_profile,
                     use_kube_naming_convention, apic_provision)
    if apic_provision.get('chained_cni_config', {}).get('primary_interface_chaining') or (
        apic_provision.get('chained_cni_config', {}).get('secondary_interface_chaining')
    ):
        verify_chained_mode_tenant_bds(apic_aci_client, tenant,
                        apic_provision['net_config']['node_subnet'],
                        use_kube_naming_convention)
    else:
        verify_tenant_bds(apic_aci_client, tenant,
                        apic_provision['net_config']['node_subnet'],
                        apic_provision['net_config']['pod_subnet'],
                        use_kube_naming_convention,
                        aci_config['system_id'])
    if apic_provision['aci_config'].get('vmm_domain'):
        # Still using acitoolkit for below test
        aci_client = lib_helper.APIC(
            user=cfg.APIC_USERNAME,
            passwd=cfg.APIC_PASSWORD,
            apic_ip=apic_provision['aci_config']['apic_hosts'][0])
        verify_vmm_domain(aci_client, aci_config['system_id'])
        verify_vmm_domain_configuration(aci_client,
                                        aci_config['system_id'],
                                        apic_provision['aci_config'][
                                            'vmm_domain']['encap_type'])


def verify_tenant(client, tenant_name):
    aci_tenant = client.get_tenant(tenant_name, subtree=False)
    assert int(aci_tenant['totalCount']) != 0, ("Specified tenant - %s does not exists "
                                    "in APIC " % tenant_name)
    LOG.info("Tenant - %s verified " % tenant_name)

def verify_vrf(client, vrf_name, tenant_name):
    vrf = client.get_vrf(vrf_name, tenant_name, subtree=False)
    assert int(vrf['totalCount']) != 0, ("VRF - %s does not exists in APIC for tenant "
                             "-%s" % (vrf_name, tenant_name))
    LOG.info("VRF - %s verified in %s tenant" % (vrf_name, tenant_name))


def verify_l3out(client, l3out_name, tenant_name):
    l3out = client.get_l3out(l3out_name, tenant_name, subtree=True)
    assert  int(l3out['totalCount']) != 0, ("L3out - %s does not exists in APIC for "
                               "tenant - %s" % (l3out_name, tenant_name))
    LOG.info("L3out - %s verified in %s tenant" % (l3out_name, tenant_name))


def verify_l3out_epg(client, l3out_name, epg_name, tenant_name):
    l3out_epg = client.get_l3out_epg(l3out_name, tenant_name, epg_name, subtree=False)
    assert int(l3out_epg['totalCount']) != 0, ("EPG - %s does not exists in L3out - %s"
                                   % (epg_name, l3out_name))
    LOG.info("L3out EPG - %s verified in %s tenant" %
             (epg_name, tenant_name))


def verify_kubernetes_ap(client, tenant_name, app_profile):
    ap = client.get_ap(tenant_name, app_profile, subtree=False)
    assert int(ap['totalCount']) != 0, ("kubernetes application profile does not exists "
                            "for tenant - %s" % tenant_name)
    LOG.info("Application Profile - %s verified in %s tenant" % (
        app_profile, tenant_name))


def verify_kube_epgs(client, tenant_name, app_profile,
                     use_kube_naming_convention, apic_provision):
    ap = client.get_ap(tenant_name, app_profile, subtree=False)
    assert int(ap['totalCount']) != 0, ("kubernetes application profile does not exists "
                            "for tenant - %s" % tenant_name)
    if apic_provision.get('chained_cni_config', {}).get('secondary_interface_chaining') or (
        apic_provision.get('chained_cni_config', {}).get('primary_interface_chaining')
    ):
        kube_epg = [cfg.ACI_CHAINED_PREFIX  + '-nodes']
    elif use_kube_naming_convention:
        kube_epg = ['kube-nodes', 'kube-system', 'kube-default']
    else:
        kube_epg = [cfg.ACI_PREFIX + '-nodes', cfg.ACI_PREFIX + '-system',
                    cfg.ACI_PREFIX + '-default']
    for _epg in kube_epg:
        epg = client.get_epg(_epg, app_profile, tenant_name, subtree=False)
        assert int(epg['totalCount']) != 0, ("%s epg does not exists in APIC for"
                                 " tenant - %s" % (app_profile, tenant_name))
        LOG.info("EPG - %s verified in %s tenant" % (app_profile, tenant_name))


def verify_chained_mode_tenant_bds(client, tenant_name, node_subnet,
                      use_kube_naming_convention):
    tenant_bds = client.get_bds(tenant_name)
    for bd in tenant_bds:
        if cfg.ACI_CHAINED_PREFIX  + '-nodes' not in bd:
            continue
        bd_detail = client.get_bd_detail(tenant_name, bd)
        LOG.info("BD - %s has theses subnets - %s" % (
            bd, bd_detail['subnets_addr_list']))
        assert (node_subnet in bd_detail['subnets_addr_list']) is True
        LOG.info("BD - %s verified in %s tenant" % (bd, tenant_name))


def verify_tenant_bds(client, tenant_name, node_subnet, pod_subnet,
                      use_kube_naming_convention, system_id,
                      use_cm_to_get_subnets=False):
    tenant_bds = client.get_bds(tenant_name)
    if use_cm_to_get_subnets:
        LOG.info("Using ConfigMap to get pod and node subnets")
        node_subnet = lib.get_node_subnets_from_cm()
        pod_subnet = lib.get_pod_subnets_from_cm()
    else : #TODO Remove this, always use ConfigMap to get subnet
        node_subnet = lib.compress_subnets(node_subnet if isinstance(node_subnet, list) else [node_subnet])
        pod_subnet = lib.compress_subnets(pod_subnet if isinstance(pod_subnet, list) else [pod_subnet])
    # Convert to set for comparission
    node_subnet = set(node_subnet)
    pod_subnet = set(pod_subnet)
    for bd in tenant_bds:
        if use_kube_naming_convention:
            if not bd.startswith('kube'):
                continue
        else: # Verify node and pod bd only
            if  not (system_id + "-node-bd" in bd or system_id + "-pod-bd" in bd):
                continue
        bd_detail = client.get_bd_detail(tenant_name, bd)
        LOG.info("BD - %s has theses subnets - %s" % (
            bd, bd_detail['subnets_addr_list']))
        bd_subnets = set(bd_detail['subnets_addr_list'])
        LOG.debug("bd_subnets %s node_subnet %s pod_subnet %s" % (bd_subnets, node_subnet, pod_subnet))
        assert (bd_subnets in (node_subnet, pod_subnet)) is True
        LOG.info("BD - %s verified in %s tenant" % (bd, tenant_name))


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


def _get_vmmdomain_info(tenant_domain, tenant_name):
    for domp in tenant_domain['imdata']:
        if domp['vmmDomP']['attributes']['name'] == tenant_name:
            vmm_dom_info = {
                k: v for k, v in domp['vmmDomP']['attributes'].items()
                if k in ['name', 'encapMode', 'prefEncapMode', 'mcastAddr',
                         'annotation']
                }
            return vmm_dom_info
