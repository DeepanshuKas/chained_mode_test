import json
import os
import time

from acc_pyutils import logger
from tests.apic_apis import ApicApi
from tests import lib

LOG = logger.get_logger(__name__)
PWD = os.path.dirname(os.path.abspath(__file__))

FILT_ENTRY_0 = "0"
FILT_ENTRY_1 = "1"
FILT_ENTRY_2 = "2"

FILT_ENTRY_0_TCP_FROM_PORT = 5000
FILT_ENTRY_0_TCP_TO_PORT = 65000

SERVICE_FILT_ENTRY_0_TCP_FROM_PORT = 9995
SERVICE_FILT_ENTRY_0_TCP_TO_PORT = 9995

FILT_ENTRY_1_UDP_FROM_PORT = 5000
FILT_ENTRY_1_UDP_TO_PORT = 65000

SERVICE_FILT_ENTRY_1_TCP_FROM_PORT = 5000
SERVICE_FILT_ENTRY_1_TCP_TO_PORT = 65000

SERVICE_FILT_ENTRY_2_UDP_FROM_PORT = 5000
SERVICE_FILT_ENTRY_2_UDP_TO_PORT = 65000


class ValidateApi(object):
    def __init__(self, kwargs):
        """Initialise apic."""
        apic_ip = kwargs['apic_host']
        apic_username = kwargs['apic_username']
        apic_password = kwargs['apic_password']
        try:
            self.aci = ApicApi(apic_ip, apic_username, apic_password)
        except Exception as ex:
            LOG.error(ex)
            raise ex
        self.system_id = kwargs['system_id']
        self.l3out = kwargs['l3out']
        self.ext_network = kwargs['ext_network']
        self.snat_ip = kwargs.get('snat_ip', None)
        self.snat_policy_for_service = kwargs.get('snat_policy_for_service', False)
        self.vrf_name = kwargs['vrf_name']
        self.result_file_name = "snat_resource_results_" + \
            time.strftime("%Y%m%d-%H%M%S")
        self.result_file = self.create_result_file()

    def create_result_file(self):
        """return absolute path of output file."""
        try:
            result_file = PWD + "/" + self.result_file_name
            # if file present, delete it
            if os.path.isfile(result_file):
                try:
                    os.remove(result_file)
                except Exception:
                    pass
            return result_file
        except Exception as err:
            msg = ("Exception occured while creating %s file, Reason %s"
                   % (result_file, err))
            LOG.error(msg)

    def append_results(self, result):
        """write result to json file."""
        with open(self.result_file, 'w') as result_file:
            json.dump(result,
                      result_file,
                      indent=4)
        msg = ("Output of Apic Validation stored in %s" % self.result_file)
        LOG.info(msg)

    def get_contract(self, contract, tenant, children=True):
        """Get contract details.

        :param contract: The name of the contract
        :param tenant: The name of the tenant
        :param children: True/False, If True then it returns
                   all children details else only self details.
        """
        cont_info = self.aci.get_contract(contract,
                                          tenant,
                                          children)
        if cont_info.get('imdata') and int(cont_info['totalCount']) != 0:
            return cont_info
        else:
            return None

    def get_l3out(self, l3out, tenant, children=True):
        """Get l3out details.

        :param l3out: The name of the l3out
        :param tenant: The name of the tenant
        :param children: True/False, If True then it returns
                   all children details else only self details.
        """
        l3out_info = self.aci.get_l3out(l3out,
                                        tenant,
                                        children)
        if l3out_info.get('imdata') and int(l3out_info['totalCount']) != 0:
            return l3out_info
        else:
            return None

    def is_abstract_graph_exist(self, graph_name):
        """Verify availablity of given abstract graph.

        :param graph_name: The name of the abstract graph
        """
        graph_info = self.aci.get_abstract_graph(graph_name,
                                                 "common",
                                                 False)
        if graph_info.get('imdata') and int(graph_info['totalCount']) != 0:
            return True
        else:
            return False

    def is_global_service_graph_exist(self):
        """Verify availablity of global service graph."""
        graph_name = self.system_id + "_" + "svc" + "_" + "global"
        graph_info = self.aci.get_abstract_graph(graph_name,
                                                 "common",
                                                 False)
        if graph_info.get('imdata') and int(graph_info['totalCount']) != 0:
            return True
        else:
            return False

    def create_custom_service_graph(self, graph_name):
        """ Creates Custom Service Graph from global service graph
        :param graph_name: The name of the custom service graph
        """
        source_graph_name = self.system_id + "_" + "svc" + "_" + "global"
        self.aci.clone_abstract_graph(graph_name, source_graph_name, "common")

    def del_custom_service_graph(self, graph_name):
        """ Delete Custom Service Graph.
        :param graph_name: The name of the custom service graph
        """
        self.aci.del_abstract_graph(graph_name, "common")
        
    def set_service_graph_template(self, graph_name, contract):
        '''
        Set L4-L7 Custom Service Graph Template for contract
        Args:
        graph(str): service graph name
        contract(str): contract name
        '''
        self.aci.set_service_graph_used_for_contract(graph_name, contract, "common")

    def is_svc_graph_used_for_contract(self, graph_name, contract):
        """Verify availablity of given abstract graph for given contract.
        :param graph_name: The name of the abstract graph
        :param contract_name: The name of the contract
        """
        graph_info = self.aci.get_service_graph_used_for_contract(contract, "common")
        if graph_info.get('imdata') and int(graph_info['totalCount']) != 0:
            imd = graph_info.get('imdata')
            selected_name = imd[0]['vzRsSubjGraphAtt']['attributes']['tnVnsAbsGraphName']
            LOG.info("selected graph name %s graph name %s" % (selected_name, graph_name))
            if selected_name == graph_name:
                return True
            else:
                return False
        else:
            return False

    def is_service_graph_instance_exist(self, graph_instance, contract):
        """Verify availablity of given service graph instance."""
        abs_graph = self.system_id + "_svc_global"
        LOG.info("Checking availability of Graph "
                 "Instance : %s" % graph_instance)
        if self.snat_policy_for_service:
            context = self.vrf_name
        else:
            context = "uni"
        graph_info = self.aci.get_service_graph_instance(abs_graph,
                                                         "common",
                                                         contract,
                                                         self.snat_policy_for_service,
                                                         context,
                                                         False)
        if graph_info.get('imdata') and int(graph_info['totalCount']) != 0:
            LOG.info("Graph Instance : %s is available" % graph_instance)
            # get graph attributes
            graph_attr = graph_info['imdata'][0]['vnsGraphInst']['attributes']
            # verify service graph instance config status
            LOG.debug("service graph details is %s" % graph_attr)
            LOG.info("verifying config status for graph "
                     "instance : %s" % graph_instance)
            if graph_attr.get("configSt") == "applied":
                LOG.info("config status is applied for %s graph"
                         " instance" % (graph_instance))
                return True
            else:
                LOG.warning("Config status is not applied for %s"
                            " graph instance" % graph_instance)
                return False
        else:
            LOG.error("Graph Instance : %s is not available" % graph_instance)
            return False

    def is_snat_svcgraph_contract_exist(self, contract):
        """Verify availablity of service graph contract.

        :param contract: The name of the contract
        """
        LOG.info("Validating contract : %s" % contract)
        cons, prov = False, False
        cons_tdn = 'uni/tn-%s/out-%s/instP-%s' % ("common",
                                                  self.l3out,
                                                  contract)
        prov_tdn = 'uni/tn-%s/out-%s/instP-%s' % ("common",
                                                  self.l3out,
                                                  self.ext_network)
        if self.snat_policy_for_service:
            prov_tdn, cons_tdn = cons_tdn, prov_tdn
        LOG.info("Check Availabiity for contract : %s" % contract)
        result = self.get_contract(contract, "common", True)
        if result:
            LOG.info("Contract %s is available" % contract)
            LOG.info("Validating provider consumer relations "
                     "of contract: %s" % contract)
            for imdata in result['imdata']:
                if "vzRtCons" in imdata:
                    cons = True
                    tdn = imdata['vzRtCons']['attributes']['tDn']
                    if tdn != cons_tdn:
                        return False
                if "vzRtProv" in imdata:
                    prov = True
                    tdn = imdata['vzRtProv']['attributes']['tDn']
                    if tdn != prov_tdn:
                        return False
            if cons and prov:
                LOG.info("Verification is successfull for provider"
                         " consumer relations of contract: %s" % contract)
                return True
            else:
                LOG.error("Verification is failed for provider"
                          " consumer relations of contract: %s"
                          " contract details is: %s" % (contract,
                                                        result.get('imdata')))
                return False
        else:
            LOG.error("Unable to find contract: %s" % contract)
            return False

    def validate_l3out(self, l3out, contract):
        """Verify availablity of l3out.

        :param l3out: The name of the l3out
        """
        LOG.info("Validating l3out : %s" % l3out)
        count = 0
        ext_inst_profile1 = 'uni/tn-%s/out-%s/instP-%s' % ("common",
                                                           l3out,
                                                           contract)
        ext_inst_profile2 = 'uni/tn-%s/out-%s/instP-%s' % ("common",
                                                           l3out,
                                                           self.ext_network)
        LOG.info("Checking Availabilty of l3out : %s" % l3out)
        result = self.get_l3out(l3out, "common", True)
        if result:
            LOG.info("L3Out : %s is available" % l3out)
            LOG.info("Validating External Network Instance Profile % s"
                     " and %s" % (contract, self.ext_network))
            if not self.verify_snat_ip_of_ext_instance_profile(l3out,
                                                               contract):
                return False
            for imdata in result['imdata']:
                if "l3extInstP" in imdata:
                    dn = imdata['l3extInstP']['attributes']['dn']
                    if dn in [ext_inst_profile1, ext_inst_profile2]:
                        count = count + 1
            if count == 2:
                return True
            else:
                return False
        else:
            LOG.info("L3Out : %s is not available" % l3out)
            return False

    @staticmethod
    def getl3extSubnet(data):
        """Get external network subnet."""
        ip = list()
        imdata = data.get('imdata')
        for item in imdata:
            if "l3extSubnet" in item:
                extsub = item["l3extSubnet"].get("attributes")
                if extsub:
                    ip.append(extsub["ip"])
        return ip

    def verify_snat_ip_of_ext_instance_profile(self, l3out, instance_profile):
        """Verify snat ip of given external network instance profile."""
        LOG.info("Verifying snat ip for external instance profile %s "
                 " of l3out %s " % (instance_profile, l3out))
        data = self.aci.get_l3out_ext_instance_profile(l3out,
                                                       instance_profile,
                                                       "common")
        # get ext subnet ip
        ip_info = self.getl3extSubnet(data)
        assert ip_info, ('External subnets not found for l3out[%s]'
            ' external instance profile [%s]' % (l3out, instance_profile))
        ip_info = lib.transform_snat_ips(ip_info)
        # verifying snat ip (without mask)
        for ip in self.snat_ip:
            if ip not in ip_info:
                LOG.error("Snat ip validation failed for ext "
                          "instance profile %s of l3out %s" % (
                           instance_profile, l3out))
                return False
        return True

    def get_selection_policy(self, tenant, contract_name,
                             graph_name, node_name, subtree=False):
        """Get selection policy details.

        :param tenant: The name of the tenant
        :param contract_name: The name of the contract
        :param graph_name: The name of the graph
        :param subtree: True/False, If True then it returns
                  all children details else only self details.
        """
        policy = self.aci.get_selection_policies(tenant,
                                                 contract_name,
                                                 graph_name,
                                                 node_name,
                                                 subtree)
        if policy.get('imdata') and int(policy['totalCount']) != 0:
            return policy
        else:
            return None

    def get_device(self, device_name):
        """Get device details.

        :param device_name: The name of the device
        """
        device = self.aci.get_device(device_name, "common", False)
        if device.get('imdata') and int(device['totalCount']) != 0:
            return device
        else:
            return None

    @staticmethod
    def extract_device_name_from_tdn(tdn):
        res = tdn.split('/')
        return res[2].split('-')[1]

    def validate_device_selections_policy(self, policy_name, contract_name,
                                          snat_policy_for_service, filtered_devices=[]):
        """Verify availability of device selections policy."""
        graph_name = self.system_id + "_svc_global"
        device_name = self.system_id + "_svc_global"
        node_name = "loadbalancer"
        redirect_policy_validate = False
        LOG.info("Checking Avilability of device selection policy: %s"
                 % policy_name)
        device_selection_policy = self.get_selection_policy("common",
                                                            contract_name,
                                                            graph_name,
                                                            node_name)
        if device_selection_policy:
            LOG.info("Device Selection policy : %s is "
                     " available" % policy_name)
            for item in device_selection_policy['imdata']:
                if "vnsLDevCtx" in item:
                    attr = item['vnsLDevCtx'].get('attributes')
                    contract_name = attr.get('ctrctNameOrLbl')
                    if not snat_policy_for_service:
                        contracts = [contract_name + '_Cons',
                                     contract_name + '_Prov']
                    else:
                        contracts = [contract_name]
                    for _contract in contracts:
                        policy = self.get_svc_redirect_policy(_contract,
                                                              "common")
                        if policy:
                            device_info = self.aci.get_device(device_name,
                                                              "common",
                                                              True)
                            policy_redirect = []
                            devices = []
                            for item in policy['imdata']:
                                if 'vnsRedirectDest' in item:
                                    attr = item['vnsRedirectDest'].get(
                                        'attributes')
                                    descr = attr.get('descr')
                                    policy_redirect.append(descr)
                            LOG.info("Device list available in redirect "
                                     "policy is %s" % policy_redirect)
                            for item in device_info['imdata']:
                                if 'vnsCDev' in item:
                                    attr = item['vnsCDev'].get('attributes')
                                    name = attr.get('name')
                                    devices.append(name)
                            LOG.info("Device list is %s" % devices)
                            LOG.info("Filtered Device list is %s", filtered_devices)
                            LOG.info("Comparing redirect device list with "
                                     "device list")
                            LOG.info("Filtered devices should not be present "
                                     "in redirect devices")

                            if all(elem not in filtered_devices for elem in policy_redirect) and \
                                all(elem in policy_redirect for elem in devices):
                                redirect_policy_validate = True
                            else:
                                LOG.info("Not all devices are present in the redirect policy")
                                LOG.info("Checking if they are present in the filtered devices")

                                unmatched_devices = set(devices) - set(policy_redirect)

                                if all(elem in unmatched_devices for elem in filtered_devices):
                                    redirect_policy_validate = True
                        else:
                            return False
        else:
            LOG.error("Unable to find %s device selection"
                      " policy" % policy_name)
            return False
        # get subtree details of device_selection_policy
        device_selection_policy_subtree = self.get_selection_policy(
            "common", contract_name, graph_name, node_name, True)
        if device_selection_policy_subtree:
            for item in device_selection_policy_subtree['imdata']:
                if "vnsRsLDevCtxToLDev" in item:
                    tdn = item['vnsRsLDevCtxToLDev']['attributes']['tDn']
                    device_name = self.extract_device_name_from_tdn(tdn)
                    if self.get_device(device_name) and \
                            redirect_policy_validate:
                        return True
            return False
        else:
            return False

    def validate_filter_and_entry(self, filter_name):
        """Verify availability of given filter and filter entry.

        :param filter_name: The name of the filter
        """
        LOG.info("Validating filter: %s " % filter_name)
        LOG.info("Verifying Availability of filter : %s" % filter_name)
        filter_info = self.is_filter_exists(filter_name, "common")
        if not filter_info:
            LOG.error("Unable to find filter : %s" % filter_name)
            return False
        LOG.info("Filter : %s is available" % filter_name)
        LOG.info("Validating filter entry: %s of "
                 "filter: %s " % (FILT_ENTRY_0, filter_name))
        # validate tcp filter entry having name "0"
        filt_entry_0 = self.aci.get_filter_entry(filter_name,
                                                 FILT_ENTRY_0,
                                                 "common",
                                                 False)
        LOG.info("Checking Availability of filter entry: %s of "
                 "filter: %s " % (FILT_ENTRY_0, filter_name))
        if filt_entry_0.get('imdata') and \
                int(filt_entry_0['totalCount']) != 0:
            LOG.info("filter entry: %s of filter: %s is available" % (
                     FILT_ENTRY_0, filter_name))
            filt_entry_attr = filt_entry_0['imdata'][0][
                'vzEntry']['attributes']
            sFromPort = filt_entry_attr['sFromPort']
            sToPort = filt_entry_attr['sToPort']
            dFromPort = filt_entry_attr['dFromPort']
            dToPort = filt_entry_attr['dToPort']
            prot = filt_entry_attr['prot']
            if not self.snat_policy_for_service:
                LOG.info("Expected protocol: tcp, Fromport: %d, ToPort: %d"
                         % (FILT_ENTRY_0_TCP_FROM_PORT,
                            FILT_ENTRY_0_TCP_TO_PORT))
                tcp_attr = {'sFromPort': sFromPort, 'sToPort': sToPort,
                            'dFromPort': dFromPort, 'dToPort': dToPort,
                            'protocol': prot}
                self._validate_tcp_attr_of_filter(filter_name, **tcp_attr)
            else:
                LOG.info("Expected protocol: tcp, Fromport: %d, ToPort: %d"
                         % (SERVICE_FILT_ENTRY_0_TCP_FROM_PORT,
                            SERVICE_FILT_ENTRY_0_TCP_TO_PORT))
                if int(dFromPort) != SERVICE_FILT_ENTRY_0_TCP_FROM_PORT \
                        or int(dToPort) != SERVICE_FILT_ENTRY_0_TCP_TO_PORT \
                        or prot != "tcp":
                    LOG.error("Found protocol:%s, Fromport:%s, ToPort:%s" % (
                              prot, sFromPort, sToPort))
        else:
            LOG.error("Unable to find filter entry: %s" % FILT_ENTRY_0)
            return False

        LOG.info("Validating filter entry: %s of "
                 "filter: %s " % (FILT_ENTRY_1, filter_name))
        # validate filter entry having name "1"
        filt_entry_1 = self.aci.get_filter_entry(filter_name,
                                                 FILT_ENTRY_1,
                                                 "common",
                                                 False)
        LOG.info("Checking Availability for filter entry: %s of "
                 "filter: %s " % (FILT_ENTRY_1, filter_name))
        if filt_entry_1.get('imdata') and int(filt_entry_1['totalCount']) != 0:
            LOG.info("filter entry: %s of filter: %s is available" % (
                     FILT_ENTRY_1, filter_name))
            filt_entry_attr = filt_entry_1['imdata'][0][
                'vzEntry']['attributes']
            sFromPort = filt_entry_attr['sFromPort']
            sToPort = filt_entry_attr['sToPort']
            dFromPort = filt_entry_attr['dFromPort']
            dToPort = filt_entry_attr['dToPort']
            prot = filt_entry_attr['prot']
            if not self.snat_policy_for_service:
                LOG.info("Expected protocol: udp, Fromport:%d, ToPort:%d"
                         % (FILT_ENTRY_1_UDP_FROM_PORT,
                            FILT_ENTRY_1_UDP_TO_PORT))
                udp_attr = {'sFromPort': sFromPort, 'sToPort': sToPort,
                            'dFromPort': dFromPort, 'dToPort': dToPort,
                            'protocol': prot}
                return self._validate_udp_attr_of_filter(
                    filter_name, **udp_attr)

            else:
                LOG.info("Expected protocol: tcp, Fromport: %d, ToPort: %d"
                         % (SERVICE_FILT_ENTRY_1_TCP_FROM_PORT,
                            SERVICE_FILT_ENTRY_1_TCP_TO_PORT))
                if int(dFromPort) != SERVICE_FILT_ENTRY_1_TCP_FROM_PORT or \
                        int(dToPort) != SERVICE_FILT_ENTRY_1_TCP_TO_PORT or \
                        prot != "tcp":
                    LOG.error("Found protocol: %s, Fromport: %s, "
                              "ToPort: %s" % (prot, sFromPort, sToPort))
                    return False
        else:
            LOG.error("Unable to find filter entry: %s" % FILT_ENTRY_1)
            return False

        if self.snat_policy_for_service:
            LOG.info("Validating filter entry: %s of "
                     "filter: %s " % (FILT_ENTRY_2, filter_name))
            # validate udp filter entry having name "2"
            filt_entry_2 = self.aci.get_filter_entry(filter_name,
                                                     FILT_ENTRY_2,
                                                     "common",
                                                     False)
            LOG.info("Checking Availability for filter entry: %s of "
                     "filter: %s " % (FILT_ENTRY_2, filter_name))
            if filt_entry_2.get('imdata') and \
                    int(filt_entry_2['totalCount']) != 0:
                LOG.info("filter entry: %s of filter: %s is available" % (
                         FILT_ENTRY_2, filter_name))
                filt_entry_attr = filt_entry_2['imdata'][0][
                    'vzEntry']['attributes']
                dFromPort = filt_entry_attr['dFromPort']
                dToPort = filt_entry_attr['dToPort']
                prot = filt_entry_attr['prot']
                LOG.info("Expected protocol: udp, Fromport: %d, ToPort: %d"
                         % (SERVICE_FILT_ENTRY_2_UDP_FROM_PORT,
                            SERVICE_FILT_ENTRY_2_UDP_TO_PORT))
                if int(dFromPort) != SERVICE_FILT_ENTRY_2_UDP_FROM_PORT or \
                        int(dToPort) != SERVICE_FILT_ENTRY_2_UDP_TO_PORT \
                        or prot != "udp":
                    LOG.error("Found protocol: %s, Fromport: %s, "
                              "ToPort: %s" % (prot, sFromPort, sToPort))
                    return False
        return True

    def is_filter_exists(self, filt_name, tenant):
        """Verify availability of provided filter.

        :param filt_name: The name of the filter
        :tenant: The name of the tenant
        """
        filter_info = self.aci.get_filter(filt_name, tenant)
        if filter_info.get('imdata') and int(filter_info['totalCount']) != 0:
            return True
        else:
            return False

    def get_svc_redirect_policy(self, policy, tenant, subtree=True):
        """Get service redirect policy.

        :param name: The name of the policy
        :param tenant: The name of the tenant
        """
        policy_info = self.aci.get_service_redirect_policy(policy,
                                                           tenant,
                                                           subtree)
        if policy_info.get('imdata') and int(policy_info['totalCount']) != 0:
            return policy_info
        else:
            return None

    @staticmethod
    def _validate_tcp_attr_of_filter(filter_name, **tcp_attr):
        if filter_name.endswith('toProv') and (
                int(tcp_attr['sFromPort']) == FILT_ENTRY_0_TCP_FROM_PORT and
                int(tcp_attr['sToPort']) == FILT_ENTRY_0_TCP_TO_PORT and
                tcp_attr['protocol'] == "tcp"):
            LOG.info("Validation for filter - %s - %s done" % (
                filter_name, tcp_attr))
            return
        elif filter_name.endswith('toCons') and (
                int(tcp_attr['dFromPort']) == FILT_ENTRY_0_TCP_FROM_PORT and
                int(tcp_attr['dToPort']) == FILT_ENTRY_0_TCP_TO_PORT and
                tcp_attr['protocol'] == "tcp"):
            LOG.info("Validation for filter - %s - %s done" % (
                filter_name, tcp_attr))
            return
        else:
            raise Exception("Filter entry - %s validation failed %s" % (
                filter_name, tcp_attr))

    @staticmethod
    def _validate_udp_attr_of_filter(filter_name, **udp_attr):
        if filter_name.endswith('toProv') and (
                int(udp_attr['sFromPort']) == FILT_ENTRY_1_UDP_FROM_PORT and
                int(udp_attr['sToPort']) == FILT_ENTRY_1_UDP_TO_PORT and
                udp_attr['protocol'] == "udp"):
            LOG.info("Validation for filter - %s - %s done" % (
                filter_name, udp_attr))
            return True
        elif filter_name.endswith('toCons') and (
                int(udp_attr['dFromPort']) == FILT_ENTRY_1_UDP_FROM_PORT and
                int(udp_attr['dToPort']) == FILT_ENTRY_1_UDP_TO_PORT and
                udp_attr['protocol'] == "udp"):
            LOG.info("Validation for filter - %s - %s done" % (
                filter_name, udp_attr))
            return True
        else:
            raise Exception("Filter entry - %s validation failed %s" % (
                filter_name, udp_attr))

    @staticmethod
    def is_vlan_encapsulation_block_exists(vlan_pool_info, vlan_from,
                                           vlan_to):
        for encap_block in vlan_pool_info:
            vlans_from = encap_block.get('fvnsEncapBlk', {}).get(
                'attributes', {}).get('from')
            vlans_to = encap_block.get('fvnsEncapBlk', {}).get(
                'attributes', {}).get('to')
            vlan_range_start = int(
                vlans_from.split('-')[1]) if vlans_from else 0
            vlan_range_end = int(
                vlans_to.split('-')[1]) if vlans_to else 0
            if vlan_from >= vlan_range_start and vlan_to <= vlan_range_end:
                return True
        return False

    def is_vlan_pool_exists(self, vlan_pool, allocation_mode, vlan_from,
                            vlan_to):
        """Verify availability of vlan pool.

        :param vlan_pool: The name of the vlan pool
        :param allocation_mode: Allocation mode of the vlan pool
        """
        LOG.info("Checking availability of vlan pool: %s" % vlan_pool)
        vlan_pool_info = self.aci.get_vlan_pool(vlan_pool, allocation_mode,
                                                self.system_id, True)

        if vlan_pool_info.get('imdata') and int(
            vlan_pool_info['totalCount']) != 0:
            if self.is_vlan_encapsulation_block_exists(
                vlan_pool_info['imdata'], vlan_from, vlan_to):
                return True
        return False
