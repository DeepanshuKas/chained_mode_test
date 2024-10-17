import requests
import warnings
import os
warnings.filterwarnings("ignore", category=DeprecationWarning)
from vmware.vapi.vsphere.client import create_vsphere_client
from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from tests.vm_migration_helper import get_apic_aci
from collections import defaultdict
from tests.input.cfg import VC_CONFIG, APIC_PROVISION_FILE
from tests import lib, lib_helper
import json
LOG = logger.get_logger(__name__)
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')


class VCenterAPIS(object):
    """This module contains vCenter  apis."""
    def __init__(self, config):
        vc_server =  config['server']
        username = config['username']
        password = config['password']
        # Skip server cert verification.
        session = self.get_unverified_session()
        # Connect to vSphere client
        try:
            self.client = create_vsphere_client(server=vc_server,
                                            username=username,
                                            password=password,
                                            session=session)
        except Exception as ex:
            raise ex

        folder_name = config.get('folder')
        folder = self.get_folder(folder_name)
        if len(folder) == 0 :
            # Scan all VMs to get the current setup folder
            LOG.info("Folder %s not found scanning...", folder_name)
            folder = self.get_setup_folder()
        assert len(folder) != 0, ("Folder %s not found Please provide correct folder name", folder_name)
        self.folder = folder[0]
        self.vms = self.get_vms_on_folder(self.folder.name)
        assert len(self.vms) != 0, ("No Vms found in folder %s", self.folder.name)
        LOG.info("%d Vms found in folder %s", len(self.vms), self.folder.name)
        # Get Cluster and Hosts Details
        cluster_name = self.get_vm_cluster(self.vms[0].name).name
        self.cluster, self.hosts = self.get_cluster_hosts(cluster_name)
        self.node_to_vm = self.map_node_to_vm()
        assert len(self.node_to_vm) != 0, ("Node to VM mapping not found for folder %s", self.folder.name)
        vm_to_node = dict()
        for node, vm in self.node_to_vm.items():
            vm_to_node.update({vm:node})
        self.vm_to_node = vm_to_node
        self.dump_node_details()

    def get_unverified_session(self):
        """
        Get a requests session with cert verification disabled.
        Also disable the insecure warnings message.
        Note this is not recommended in production code.
        @return: a requests session with verification disabled.
        """
        session = requests.session()
        session.verify = False
        requests.packages.urllib3.disable_warnings()
        return session

    def list_vc_resources(self, resourceObj, filterName=None, filterSpec=None):
        if filterSpec:
            filter_spec = filterSpec
        elif filterName:
            filter_spec = resourceObj.FilterSpec(names=set([filterName]))
        else:
            filter_spec = resourceObj.FilterSpec()

        # Always return Active VMs and Hosts
        if resourceObj == self.client.vcenter.VM :
            filter_spec.power_states = set(['POWERED_ON'])
        elif resourceObj == self.client.vcenter.Host :
            filter_spec.connection_states = set(['CONNECTED'])

        resource = resourceObj.list(filter_spec)
        LOG.debug(filter_spec)
        LOG.debug(resource)
        return resource

    def get_folder(self, name):
        return self.list_vc_resources(self.client.vcenter.Folder, name)

    def get_vm(self, name):
        return self.list_vc_resources(self.client.vcenter.VM, name)

    def get_host(self, name):
        return self.list_vc_resources(self.client.vcenter.Host, name)

    def get_cluster(self, name):
        return self.list_vc_resources(self.client.vcenter.Cluster, name)

    def get_datastore(self, name):
        return self.list_vc_resources(self.client.vcenter.Datastore, name)

    def get_vm_from_node(self, node):
        return self.node_to_vm.get(node)

    def get_node_from_vm(self, vm):
        return self.vm_to_node.get(vm)

    def get_cluster_hosts(self, cluster_name):
        cluster = self.get_cluster(cluster_name)
        filter_spec = self.client.vcenter.Host.FilterSpec(clusters=set([cluster[0].cluster]))
        hosts = self.list_vc_resources(self.client.vcenter.Host, None, filter_spec)
        return cluster, hosts

    def is_vm_exist(self, filterSpec):
        vm = self.list_vc_resources(self.client.vcenter.VM, filterSpec=filterSpec)
        if vm:
            return True
        return False

    def get_vm_host(self, name):
        for host in self.hosts:
            filter_spec = self.client.vcenter.VM.FilterSpec(
                    names=set([name]), hosts=set([host.host]))
            if self.is_vm_exist(filter_spec):
                LOG.debug("Found VM %s Running on %s : %s", name, host.host, host.name)
                return host

    def get_node_host(self, node):
        vm = self.node_to_vm.get(node)
        host_summary = self.get_vm_host(vm)
        return host_summary.name

    def get_vm_cluster(self, name):
        clusters = self.list_vc_resources(self.client.vcenter.Cluster)
        for cluster in clusters:
            filter_spec = self.client.vcenter.VM.FilterSpec(
                    names=set([name]), clusters=set([cluster.cluster]))
            if self.is_vm_exist(filter_spec):
                LOG.debug("Found VM %s Running on %s : %s", name, cluster.cluster, cluster.name)
                return cluster
        return None

    def get_vm_folder(self, name):
        folders = self.list_vc_resources(self.client.vcenter.Folder)
        for folder in folders:
            filter_spec = self.client.vcenter.VM.FilterSpec(
                    names=set([name]), folders=set([folder.folder]))
            if self.is_vm_exist(filter_spec):
                LOG.debug("Found VM %s Running on %s : %s", name, folder.folder, folder.name)
                return [folder]
        return []

    def get_vms_on_folder(self, folder_name):
        folder = self.get_folder(folder_name)
        filter_spec = self.client.vcenter.VM.FilterSpec(folders=set([folder[0].folder]))
        return self.list_vc_resources(self.client.vcenter.VM, None, filterSpec=filter_spec)

    def get_vms_on_host(self, host_name):
        host = self.get_host(host_name)
        filter_spec = self.client.vcenter.VM.FilterSpec(hosts=set([host[0].host]))
        return self.list_vc_resources(self.client.vcenter.VM, None, filterSpec=filter_spec)

    def get_vms_on_host_and_folder(self, host_name):
        host = self.get_host(host_name)
        filter_spec = self.client.vcenter.VM.FilterSpec(hosts=set([host[0].host]),
                                                        folders=set([self.folder.folder]))
        return self.list_vc_resources(self.client.vcenter.VM, None, filterSpec=filter_spec)

    def get_vm_mac(self, vm_id):
        mac = list()
        vm_info = self.client.vcenter.VM.get(vm_id)
        for k, v in vm_info.nics.items():
            mac.append(v.mac_address)
        return mac

    def get_vm_dest_hosts(self, name):
        dest_hosts = list()
        for host in self.hosts:
            filter_spec = self.client.vcenter.VM.FilterSpec(
                    names=set([name]), hosts=set([host.host]))
            if not self.is_vm_exist(filter_spec):
                dest_hosts.append(host)
        return dest_hosts

    def get_setup_folder(self):
        vms = self.list_vc_resources(self.client.vcenter.VM)
        nodes = KubeAPI().get_detail('nodes')
        for node in nodes['items']:
            svc_ep = json.loads(node['metadata']['annotations']['opflex.cisco.com/service-endpoint'])
            node_mac = svc_ep.get('mac', None)
            node_name = node['metadata']['name']
            for vm in vms:
               vm_macs = self.get_vm_mac(vm.vm)
               for vm_mac in vm_macs:
                   if vm_mac.upper() == node_mac.upper():
                       folder = self.get_vm_folder(vm.name)
                       if folder:
                           LOG.info("Node : %s found in Folder : %s", node_name, folder[0].name)
                           return folder
        return []

    def map_node_to_vm(self, folder_name=None):
        if folder_name is not None:
            vms = self.get_vms_on_folder(folder_name)
        else:
            vms = self.vms
        node_to_vm = dict()
        nodes = KubeAPI().get_detail('nodes')
        for node in nodes['items']:
            svc_ep = json.loads(node['metadata']['annotations']['opflex.cisco.com/service-endpoint'])
            node_mac = svc_ep.get('mac', None)
            node_name = node['metadata']['name']
            LOG.debug("%s : MAC %s", node_name, node_mac)
            for vm in vms:
               vm_macs = self.get_vm_mac(vm.vm)
               for vm_mac in vm_macs:
                   if vm_mac.upper() == node_mac.upper():
                       node_to_vm.update({node_name: vm.name})
                       LOG.debug("%s : %s", node_name, vm.name)

        return node_to_vm

    def get_nodes_on_host(self, host_name, skip_node=''):
        nodes = list()
        vms = self.get_vms_on_host_and_folder(host_name)
        LOG.debug(vms)
        for vm in vms:
            node = self.get_node_from_vm(vm.name)
            if node is None:
                continue
            if node == skip_node:
                LOG.info("Skiping %s", skip_node)
                continue
            nodes.append(node)
        LOG.debug("Nodes : %s", nodes)
        return nodes

    def get_vm_ds(self, name):
        vm = self.get_vm(name)
        vm_info = self.client.vcenter.VM.get(vm[0].vm)
        ds = list()
        for k, v in vm_info.disks.items():
            ds.append(v.backing.vmdk_file.split(" ")[0][1:-1])
        return list(set(ds))

    def get_host_ds(self, name):
        ds = []
        # First check on current folder vms
        vms = self.get_vms_on_host_and_folder(name) + self.get_vms_on_host(name)
        for vm in vms:
            ds_name = self.get_vm_ds(vm.name)
            LOG.debug("VM %s DS %s", vm.name, ds_name)
            ds = self.get_datastore(ds_name[0])
            if ds:
                break
        return ds

    def get_leaf_and_ds_for_host(self, name):
        vms = self.get_vms_on_host_and_folder(name) + self.get_vms_on_host(name)
        aci = get_apic_aci()
        for vm in vms:
            vm_mac_list = self.get_vm_mac(vm.vm)
            # Get the opflex device details for a specific compute host
            if len(vm_mac_list) == 0:
                continue
            for vm_mac in vm_mac_list:
                opflex_device_details = aci.get_opflexODev_for_mac(vm_mac)
                for opflex_device in opflex_device_details["imdata"]:
                    fabricPathDn = opflex_device["opflexODev"]["attributes"]["fabricPathDn"]
                    if fabricPathDn:
                        # Parse the fabricPathDn to extract only the leaf name
                        leafName = fabricPathDn.split("/")[2]
                        if leafName:
                            ds_name = self.get_vm_ds(vm.name)
                            LOG.debug("VM %s Leaf : %s Host : %s DS %s",
                                    vm.name, leafName, name, ds_name)
                            return leafName, ds_name[0]
        return '', ''

    def get_leaf_to_compute_host_mapping(self):
        leaf_to_compute_host_mapping  = defaultdict(list)
        for host in self.hosts:
            leafName, ds_name = self.get_leaf_and_ds_for_host(host.name)
            if leafName:
                detail = { 'host' : host.name,
                           'ds' : ds_name
                        }
                leaf_to_compute_host_mapping[leafName].append(detail)
        LOG.debug(leaf_to_compute_host_mapping)
        return leaf_to_compute_host_mapping

    def set_leaf_to_host(self, leaf_to_host):
        self.leaf_to_host = leaf_to_host

    def dump_leaf_to_host(self):
        for leaf, hosts in self.leaf_to_host.items():
            LOG.info("leaf name : %s", leaf)
            for host in hosts:
                LOG.info("    %s", host)

    # Debug function
    def get_host_ds_mapping(self):
        host_to_ds = dict()
        for host in self.hosts:
            ds = self.get_host_ds(host.name)
            info = {
                    'host' : host,
                    'ds' : ds[0]
            }
            host_to_ds.update({host.name:info})
        return host_to_ds

    def get_host_ds_from_map(self, host):
        return self.host_to_ds.get(host).get("ds")

    def dump_node_details(self, node_name=None):
        nodes_info = {}
        if not hasattr(self, 'host_to_ds'):
            self.host_to_ds = self.get_host_ds_mapping()
        for vm in self.vms:
            if node_name and vm.name != self.get_vm_from_node(node_name):
                continue
            nodename = self.get_node_from_vm(vm.name)
            host = self.get_vm_host(vm.name)
            ds = self.get_host_ds_from_map(host.name)
            node_info = {
                'nodename' : nodename,
                'vmname' : vm.name,
                'host' : host.name,
                'ds' : ds.name,

            }
            LOG.debug("Node : %s  VM : %s Host : %s DS : %s",
                     nodename, vm.name, host.name, ds.name)
            nodes_info.update({nodename : node_info})

        for _, node_info in nodes_info.items():
            LOG.info(node_info)

        return nodes_info
    #End of debug function

    def get_relocateSpec(self, dest):
        dest_host = dest.get('host', None)
        dest_ds = dest.get('ds', None)
        if dest_host is not None:
            host = self.get_host(dest_host)
            assert len(host) != 0, ("Invalid Host Name %s", dest_host)
            dhost = host[0]
        ds_id = None
        if dest_ds is not None:
            ds_summary = self.get_datastore(dest_ds)
            assert len(ds_summary) != 0 , ("Invaild Datastore %s", dest_ds)
            ds_id = ds_summary[0].datastore

        LOG.info("relocateSpec Host : %s DS %s", dhost, dest_ds)
        placementSpec = self.client.vcenter.VM.RelocatePlacementSpec(
            host=dhost.host,
            datastore=ds_id)
        relocateSpec = self.client.vcenter.VM.RelocateSpec(placement=placementSpec)
        LOG.info(relocateSpec)
        return relocateSpec

    def live_migrate_vm(self, name, dest):
        vm = self.get_vm(name)
        vm_host = self.get_vm_host(name)
        LOG.info("Migrating VM %s from host %s", vm, vm_host)
        relocateSpec = self.get_relocateSpec(dest)
        task = self.client.vcenter.VM.relocate_task(vm[0].vm, relocateSpec)
        LOG.info(task.get_info())
        return task

    def live_migrate_node(self, node, dest):
        vm = self.get_vm_from_node(node)
        return self.live_migrate_vm(vm, dest)

    # Helper function
    def is_valid_cluster_for_intra_leaf_migration(self):
        intra_leaf = False
        for leaf, hosts in self.leaf_to_host.items():
            if len(hosts) > 1 :
                intra_leaf = True
        return intra_leaf

    def is_valid_cluster_for_inter_leaf_migration(self):
        inter_leaf = False
        if len(self.leaf_to_host) >= 2:
            inter_leaf = True
        return inter_leaf

    def is_valid_node_for_intra_leaf_migration(self, node_name):
        node_host = self.get_node_host(node_name)
        host_leaf = self.get_host_leaf(node_host)
        hosts = self.leaf_to_host.get(host_leaf, [])
        if len(hosts) > 1:
            return True
        return False

    def is_valid_node_for_inter_leaf_migration(self, node_name):
        node_host = self.get_node_host(node_name)
        _, host = self.get_leaf_and_host_for_inter_leaf_test(node_host)
        if len(host) != 0:
            return True
        return False

    def get_valid_node_for_migration(self, inter_leaf=True, node_list=[]):
        valid_node = []
        if len(node_list) == 0:
            # Get List of all available node
            node_list =  lib.get_all_nodes_hostname_with_ready_state()
        for node in node_list:
            if inter_leaf:
                if self.is_valid_node_for_inter_leaf_migration(node):
                    valid_node.append(node)
            else:
                if self.is_valid_node_for_intra_leaf_migration(node):
                    valid_node.append(node)
        return valid_node

    def get_valid_node_not_running_on_host(self, host_name, inter_leaf=True):
        valid_node = []
        host_leaf = self.get_host_leaf(host_name)
        for leaf, hosts in self.leaf_to_host.items():
            if inter_leaf and host_leaf == leaf:
                continue
            elif not inter_leaf and host_leaf != leaf:
                continue
            for host in hosts:
               nodes = self.get_nodes_on_host(host.get('host'))
               valid_node.extend(nodes)
        return valid_node

    def get_host_leaf(self, host_name):
        for leaf, hosts in self.leaf_to_host.items():
            for host in hosts:
                if host.get('host') == host_name:
                    return leaf
        return None

    def get_leaf_and_host_for_intra_leaf_test(self, host_name):
        leaf = self.get_host_leaf(host_name)
        hosts = self.leaf_to_host.get(leaf)
        for host in hosts:
            if host.get('host') != host_name:
                return leaf, host
        return '', {}

    def get_leaf_and_host_for_inter_leaf_test(self, host_name):
        host_leaf = self.get_host_leaf(host_name)
        for leaf, hosts in self.leaf_to_host.items():
            if leaf == host_leaf:
                continue
            for host in hosts:
                if host.get('host') != host_name:
                    return leaf, host
        return "", {}

    def get_host_details(self, host_name):
        for leaf, hosts in self.leaf_to_host.items():
            for host in hosts:
                if host.get('host') == host_name:
                    return leaf, host
        return "", []

    def get_controller_node_and_host(self):
        controller_node = lib_helper.get_acc_controller_running_node()
        controller_host =  self.get_node_host(controller_node)
        LOG.info("Controller Node %s Running on Host %s", controller_node, controller_host)
        return controller_node, controller_host

def get_vcenter_obj():
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    system_id = apic_provision['aci_config']['system_id']
    host =  VC_CONFIG.get('IP', "Please Provide vCenter client IP")
    username = VC_CONFIG.get('USER', "Please Provide vCenter UserName")
    passwd = VC_CONFIG.get('PASSWD', "Please Provide vCenter Password")

    # Optional config, incase not provided the script will automatically
    folder = VC_CONFIG.get('FOLDER', system_id)

    config = {
        'server': host,
        'username': username,
        'password': passwd,
        'folder': folder,
    }

    try:
        vc = VCenterAPIS(config)
    except Exception as ex:
        assert False, ("Failed to connect vCenter client : %s"
                       " Verify %s file", ex, CONFIG_FILE)

    LOG.info("vCenter Login Success")
    return vc
