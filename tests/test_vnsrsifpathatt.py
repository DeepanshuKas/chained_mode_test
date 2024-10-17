
import json

import pytest
import tests.vm_migration_helper as vm_helper
from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib

LOG = logger.get_logger(__name__)

def is_openshift_on_openstack():
    # Get the config map
    try:
        config_map = lib.get_detail('ConfigMap', 
                                    name='aci-containers-config',
                                    namespace='aci-containers-system')
    
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist, aci-containers-config")
        assert False, ("Validating config map failed, Reason: %s" % e.message) 
        
    # Check if the platform is OpenStack by checking the flavor
    config_map['data']['controller-config'] = json.loads(config_map['data']['controller-config'])
    flavor = config_map['data']['controller-config'].get('flavor','')
    
    if 'openstack' in flavor:
        return True
    return False

@pytest.mark.skipif(is_openshift_on_openstack() == False, reason='not openstack related')
@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
def test_vnsrsifpathatt_for_hosts_and_nodes(base_fixture):
    LOG.info("Checking if vnsRsCIfPathAtt created for each OpenStack compute hosts "
             "along with OpenShift nodes")
    # Get the list of OpenStack compute hosts
    oapi = vm_helper.OpenstackAPI()
    hosts = oapi.list_hosts()
    # Get the list of OpenShift nodes
    nodes = oapi.list_compute_nodes()
    ready_nodes =  lib.get_all_nodes_hostname_with_ready_state()
    # APIC api
    aci = vm_helper.get_apic_aci()
    # Check if vnsRsCIfPathAtt present for each OpenStack compute hosts along with OpenShift nodes
    for host in hosts:
        host_name = host.split('.')[0]
        LOG.info("Checking vnsRsCIfPathAtt for compute host %s" % host_name)
        vnsRsCIfPathAtt_details = aci.get_vnsRsCIfPathAtt_for_host(host_name)
        vnsRsCIfPathAtt_count = int(vnsRsCIfPathAtt_details.get('totalCount', 0))
        assert vnsRsCIfPathAtt_count > 0, ("Failed to get vnsRsCIfPathAtt for host %s" % host_name)
        LOG.info("vnsRsCIfPathAtt details for compute host %s : %s" % (host_name, vnsRsCIfPathAtt_details))

    for node_name in nodes:
        if node_name not in ready_nodes:
            LOG.warning("node_name %s not Ready" % node_name)
            continue
        LOG.info("Checking vnsRsCIfPathAtt for OpenShift node %s" % node_name)
        vnsRsCIfPathAtt_details = aci.get_vnsRsCIfPathAtt_for_host(node_name)
        vnsRsCIfPathAtt_count = int(vnsRsCIfPathAtt_details.get('totalCount', 0))
        assert vnsRsCIfPathAtt_count > 0, ("Failed to get vnsRsCIfPathAtt for node %s" % node_name)
        LOG.info("vnsRsCIfPathAtt details for OpenShift node %s : %s" % (node_name, vnsRsCIfPathAtt_details))
