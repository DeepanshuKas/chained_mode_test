import os
import openstack
import time

from acc_pyutils import logger
from acc_pyutils.utils import retry
import tests.input.cfg as cfg
from tests import lib_helper
from tests.apic_apis import ApicApi
from collections import defaultdict

LOG = logger.get_logger(__name__)
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')
DEFAULT_MAX_MIGRATION_COUNT = 1
#Deault Timeot in Second
DEFAULT_NODE_WAIT_TIMEOUT = 20 * 60
DEFAULT_TRAFFIC_RESUME_TIMEOUT = 20 * 60
DEFAULT_VM_MIGRATION_TIMEOUT = 5400
INTERVAL = 20
overCloud = '/acc-pytests/tests/input/overcloudrc'

class OpenstackAPI:
    """
    This class is a wrapper of Openstack cli utility. It executes
    the api call and return the STDOUT output to caller. By default, it logs
    all the output in syslog of the host.

    usage:
    oapi = OpenstackAPI()
    oapi.list_compute_nodes()

    """
    def __init__(self):
        # It to set environment variable for openstack api
        with open(overCloud, 'r') as fh:
            env_dict = dict(
                tuple(line.replace('\n', '').split(' ')[1].split('='))
                for line in fh.readlines() if line.startswith('export')
            )
        os.environ.update(env_dict)
        self.conn = openstack.connect()
        admin_project_name = getattr(cfg, 'OPENSHIFT_ADMIN_OS_PROJECT_NAME', "admin")
        self.admin_project = self.conn.connect_as_project(admin_project_name)

    def list_hosts(self):
        """
        Execute openstack hosts list

        :return: returns all compute hosts from the hypervisor api
        """
        hosts = []
        for hypervisor in self.admin_project.list_hypervisors():
            state = hypervisor.to_dict()['state']
            if state == "up":
                hosts.append(hypervisor.to_dict()['name'])
        return hosts

    def get_host_free_resources_info(self, host_name):
        """
        Execute openstack hosts list
        :param node_id: compute host name

        :return: returns free resources{disk, ram, vcpus} of host
        """
        resc_info = {'disk' : 0, 'ram' : 0, 'vcpus' : 0}
        for hypervisor in self.admin_project.list_hypervisors():
            hypervisor_dict = hypervisor.to_dict()
            if host_name != hypervisor_dict['name']:
                continue
            resc_info['disk'] = hypervisor_dict['local_disk_free']
            resc_info['ram'] = hypervisor_dict['memory_free']
            resc_info['vcpus'] = hypervisor_dict['vcpus'] - hypervisor_dict['vcpus_used'] 
        return resc_info  

    def list_compute_nodes(self):
        """
        Execute openstack server list

        :return: returns all master and worker nodes name
        """
        nodes = []
        for server in self.conn.compute.servers():
            nodes.append(server.to_dict()['name'])
        return nodes

    def list_nodes_with_info(self):
        """
        Exexute openstack server list

        :return: returns all nodes name with ID and comuter host of that in dictonary format.
        """
        nodes = {}
        for server in self.conn.compute.servers():
            nodes[server.to_dict()['name']] = self.get_node_details(server.to_dict()['name'])
        return nodes

    def get_node_details(self, node_name):
        """
        Execute openstack server list

        :param node_name: Name of the instance
        :return: returns ID, status and compute host of the instance
        """
        dict = {}
        nodes = self.get_cluster_node_names_with_id()
        node_id = nodes[node_name]
        node_data = self.get_node_details_by_id(node_id)
        dict['name'] = node_name
        dict['ID'] = node_data['id']
        dict['Status'] = node_data['status']
        dict['Compute Host'] = node_data['compute_host']
        flavor = node_data['flavor']
        dict['Specs'] = {'ram' : flavor['ram'], 'vcpus' : flavor['vcpus'], 'disk' : flavor['disk']} 
        return dict

    def get_node_status(self, node_id):
        """
        Execute openstack server show $node_id

        :param node_id: Id of the instance
        :return: returns current status of the instance
        """
        instance_data = self.conn.compute.get_server(node_id)
        instance_data = instance_data.to_dict()
        status = instance_data['status']
        return status

    def get_cluster_node_names_with_id(self):
        """
        Execute openstack server list

        :return: returns all node name with id
        """
        nodes = {}
        for server in self.conn.compute.servers():
            nodes[server.to_dict()['name']] = server.to_dict()['id']
        return nodes

    def get_node_details_by_id(self, node_id):
        """
        Execute openstack server show $node_id

        :param node_id: Id of the instance
        :return: returns details of the instance
        """
        instance_data = self.conn.compute.get_server(node_id)
        instance_data = instance_data.to_dict()
        return instance_data

    def vm_live_migrate(self, node_id, dest_host):
        """
        Execute openstack server migrate $node_id --block-migration --live $dest_host

        :param node_id: Instance Id which needs to migrate
        :param dest_host: Destination compute host name
        :return:
        """
        self.conn.compute.live_migrate_server(node_id, host=dest_host, block_migration=True)

    def check_status_migration(self, node_id):
        """
        Check the status of instance.
        It will wait till the status became ACTIVE or maximum time reached

        :param node_id: Instance Id
        :return:
        """
        max_time = time.time() + DEFAULT_VM_MIGRATION_TIMEOUT
        while True:
            instance_data = self.conn.compute.get_server(node_id)
            instance_data = instance_data.to_dict()
            status = instance_data['status']
            LOG.info("Live migration status is: %s" % status)
            if status == "ACTIVE" or time.time() >= max_time:
                break
            time.sleep(INTERVAL)
        LOG.info("Live Migration status is: %s" % status)

@retry(no_of_retry=2)
def get_apic_aci():
    # Initialize APIC api
    apic_provision = lib_helper.get_apic_provision_input(
        cfg.APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    try:
        aci = ApicApi(apic_host, cfg.APIC_USERNAME, cfg.APIC_PASSWORD)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))
    return aci

def get_node_opflexODev_details(aci, node_name):
    # Get the opflex device details for a specific node
    opflexODev_details = defaultdict(dict)
    opflex_device_details = aci.get_opflexODev_for_host(node_name)
    if int(opflex_device_details['totalCount']) == 0:
        LOG.info("opflexODev not found for %s" % node_name)
        return opflexODev_details
    elif opflex_device_details.get('imdata', None) is not None:
        LOG.info("%s opflexODev found for %s" % (opflex_device_details['totalCount'], node_name))
    else :
        assert False, ("Failed to get opflexODev details for %s" % node_name)

    #Get leafPair opflexODev mapping
    # Ex : {"leafPair" : {'Primary': {opflexODev}, 'Secondary': {opflexODev}}, ...}
    LOG.debug("opflexODev device details %s" % opflex_device_details)
    for opflexODev in opflex_device_details.get('imdata'):
        attrs = opflexODev['opflexODev']['attributes']
        leafPair = attrs['fabricPathDn'].split("/")[2]
        isSecondary =  attrs['isSecondary']
        leafType = 'Secondary' if isSecondary == "true" else 'Primary'
        odev_info = {
            leafType : {
                'leafName' : attrs['dn'].split("/")[2],
                'state': attrs['state'],
                'fabricPathDn' : attrs['fabricPathDn'],
                #'leafPair' : leafPair,
                #'devId' : attrs['devId']
            }
        }
        opflexODev_details[leafPair].update(odev_info)
    return opflexODev_details

def is_opflexODev_leafPair_disconnected(aci, node_name, lp):
    opflexODev_details = get_node_opflexODev_details(aci, node_name)
    #leafPair not exist
    if len(opflexODev_details) == 0 or opflexODev_details.get(lp, None) is None:
        return False
    for lpt, opflexODev in opflexODev_details[lp].items():
        if opflexODev['state'] == "disconnected":
            return True
    return False

def is_opflexODev_leafPair_deleted(aci, node_name, lp):
    opflexODev_details = get_node_opflexODev_details(aci, node_name)
    if len(opflexODev_details) == 0 or opflexODev_details.get(lp, None) is None:
        LOG.info("leafPair %s deleted" % lp)
        return True
    for lpt, opflexODev in opflexODev_details[lp].items():
        LOG.info("%s opflexODev not deleted %s" % (lpt, opflexODev))
    return False

def is_new_opflODev_leafPair_created(aci, node_name, old_lp):
    opflexODev_details = get_node_opflexODev_details(aci, node_name)
    if len(opflexODev_details) == 0:
        return False, None
    for lp, opflexODev_detail in opflexODev_details.items():
        if lp != old_lp:
            if len(opflexODev_detail) == 2:
                LOG.debug("new leafPair %s : %s" % (lp, opflexODev_detail))
                return True, opflexODev_detail
    return False, None

def get_node_opflexODev_prog_time(node_name, old_lp, timeout=15* 60, wait_for_delete=False):
    prog_time = dict()
    max_time = time.time() + timeout
    start_time = time.time()
    deleted = created = disconnected = False
    while time.time() < max_time:
        aci = get_apic_aci()
        if not created:
            created, new_opflexODev_detail = is_new_opflODev_leafPair_created(aci, node_name, old_lp)
            if created:
                time_diff = int(time.time() - start_time)
                prog_time.update({'created' : time_diff})
                LOG.info("opflexODev created in %s Sec." % time_diff)
        if not deleted:
            deleted = is_opflexODev_leafPair_deleted(aci, node_name, old_lp)
            if deleted :
                time_diff = int(time.time() - start_time)
                prog_time.update({'deleted' : time_diff})
                LOG.info("opflexODev deleted in %s Sec." % time_diff)
        if not disconnected:
            disconnected = is_opflexODev_leafPair_disconnected(aci, node_name, old_lp)
            if disconnected :
                time_diff = int(time.time() - start_time)
                prog_time.update({'disconnected' : time_diff})
                LOG.info("opflexODev disconnected in %s Sec." %  time_diff)
        if created and (deleted or (not wait_for_delete and disconnected)):
            LOG.info("opflexODev new %s old %s Re-created in %s Sec." %
                     (new_opflexODev_detail, old_lp, (time.time() - start_time)))
            break
        time.sleep(INTERVAL)
    LOG.info(prog_time)

    return created, prog_time

def get_node_L4L7Device_details(aci, node_name):
    # Get the L4L7 device details for a specific node
    L4L7Device_details = defaultdict(dict)
    vnsRsCIfPathAtt_details = aci.get_vnsRsCIfPathAtt_for_host(node_name)
    if int(vnsRsCIfPathAtt_details['totalCount']) == 0:
        LOG.info("vnsRsCIfPathAtt not found for %s" % node_name)
        return L4L7Device_details
    elif vnsRsCIfPathAtt_details.get('imdata', None) is not None:
        LOG.info("%s vnsRsCIfPathAtt found for %s" %
                 (vnsRsCIfPathAtt_details['totalCount'], node_name))
    else :
        assert False, ("Failed to get vnsRsCIfPathAtt details for %s" % node_name)
    LOG.debug("vnsRsCIfPathAtt device details %s" % vnsRsCIfPathAtt_details)
    vnsAtt = vnsRsCIfPathAtt_details['imdata'][0]['vnsRsCIfPathAtt']['attributes']
    tDn = vnsAtt['tDn']
    leafPair = tDn.split("/")[2]
    L4L7Device_details[leafPair].update({'tDn': tDn})
    LOG.info(L4L7Device_details)
    return L4L7Device_details

def validate_node_opflexODev_and_L4L7_device_sync(node_name, timeout=60):
    sync = False
    time_diff = timeout
    start_time = time.time()
    max_time = start_time + timeout
    while time.time() < max_time:
        aci = get_apic_aci()
        opflexODev_details = get_node_opflexODev_details(aci, node_name)
        L4L7Device_details = get_node_L4L7Device_details(aci, node_name)
        if len(L4L7Device_details) == 0 or len(opflexODev_details) == 0:
            LOG.warning("opflexODev_details or L4L7Device_details not found!")
            time.sleep(INTERVAL)
            continue
        for lp, opflexODev_detail in opflexODev_details.items():
            L4L7Device_detail = L4L7Device_details.get(lp, None)
            if L4L7Device_detail is None:
                LOG.warning("L4L7Device_detail not found for LP %s on node %s" % (lp, node_name))
                continue
            status = list()
            # compair both Primary and Secondary opflexODev of node
            for leafType, opflexODev in opflexODev_detail.items():
                st = False
                if opflexODev['state'] == "disconnected":
                    status.append(st)
                    continue
                if L4L7Device_detail['tDn'] == opflexODev['fabricPathDn']:
                    LOG.info("%s synced" % (leafType))
                    st = True
                else:
                    LOG.warning("ODEV: %s and L4L7Device: %s information are out of sync!." %
                              (opflexODev['fabricPathDn'], L4L7Device_detail['tDn']))
                status.append(st)
            if all(status):
                sync = True
                break
        if sync:
            time_diff = int(time.time() - start_time)
            LOG.info("opflexODev and L4L7Device information are synced in %d Sec." % time_diff)
            break
        time.sleep(INTERVAL)
    return sync, time_diff
    
def get_node_opflexODev_leafPair(node_name):
    aci = get_apic_aci()
    opflexODev_details = get_node_opflexODev_details(aci, node_name)
    if len(opflexODev_details) == 0:
        return None
    for lp, opflexODev in opflexODev_details.items():
        #Check for both Primary and Secondary opflexODev
        if len(opflexODev) == 2:
            LOG.debug("%s : %s" % (lp, opflexODev))
            return lp
    return None

def get_leaf_to_compute_host_mapping():
    leaf_to_compute_host_mapping  = defaultdict(list)
    oapi = OpenstackAPI()
    # Get Compute Host to Leaf mapping
    compute_hosts = oapi.list_hosts()
    # Initialize APIC api
    aci = get_apic_aci()
    for compute_host in compute_hosts:
        # Only the prefix is required.
        hostname_prefix = compute_host.split(".")
        if not hostname_prefix:
            continue
        # Get the opflex device details for a specific compute host
        opflex_device_details = aci.get_opflexODev_for_host(hostname_prefix[0])
        for opflex_device in opflex_device_details["imdata"]:
            fabricPathDn = opflex_device["opflexODev"]["attributes"]["fabricPathDn"]
            if fabricPathDn:
                # Parse the fabricPathDn to extract only the leaf name
                leafName = fabricPathDn.split("/")[2]
                if leafName:
                    leaf_to_compute_host_mapping[leafName].append(compute_host)

    # Unique host 
    LOG.info("LEAF_TO_COMPUTE_HOST_MAPPING")
    for leaf, hosts in leaf_to_compute_host_mapping.items():
        leaf_to_compute_host_mapping[leaf] = list(set(hosts))
        LOG.info("%s:%s" % (leaf, leaf_to_compute_host_mapping[leaf]))

    LOG.info("%d LeafPair found" % len(leaf_to_compute_host_mapping))
    return leaf_to_compute_host_mapping

def dump_migration_stats(result):
    test_status = True
    LOG.info("=======VM Migration Info Start ========")
    for migration_info in result:
        LOG.info("=== %s VM Migration Info ===" % migration_info.get('type', 'Unknown'))
        for k, v in migration_info.items():
            LOG.info("%s : %s %s" % (k, str(v), "Sec" if "time" in k else ""))
            if "FAILED" in str(v):
                    test_status = False
            elif "Traffic_Test_During_Migration" == k:
                if v.get('Failed', 0) != 0:
                    test_status = False
        LOG.info("=============================")
    LOG.info("=======VM Migration Info End ========")
    return test_status
