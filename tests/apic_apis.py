import json
import requests

from acc_pyutils import logger
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import threading
import time

LOG = logger.get_logger(__name__)
base_url = '/api/node/mo/uni/'

TOKEN_REFRESH_TIME = 300

class ApicApi(object):
    """This module contains apic get apis."""

    def __init__(self, apic_ip, username='admin',
                 password='noir0123', ssl=True):
        """intialise apic."""
        self.addr = apic_ip
        self.ssl = ssl
        self.user = username
        self.passwd = password
        self.cookies = None
        self.token_expiry_time = TOKEN_REFRESH_TIME
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        if not self.login():
            msg = "Could not able to login into APIC, Check apic creds."
            raise Exception(msg)

        """ Thread to refresh the token after 5 minutes. """
        self.start_refresh_thread()

    def url(self, path):
        """get apic url with given path."""
        if self.ssl:
            return 'https://%s%s' % (self.addr, path)

    def login(self):
        """apic login."""
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' \
            % (self.user, self.passwd)
        path = '/api/aaaLogin.json'
        try:
            req = requests.post(self.url(path), data=data, verify=False)
        except requests.exceptions.RequestException as ex:
            LOG.error(ex)
            return None
        if req.status_code == 200:
            resp = json.loads(req.text)
            token = resp['imdata'][0]['aaaLogin']['attributes']['token']
            self.cookies = {'APIC-Cookie': token}
            return req
        elif req.status_code == 503:
            msg = ("Server is too busy, Please try after some time, status code = 503")
            LOG.warning(msg)
            return None
        else:
            msg = ("Post request failed with status code = %s"
                   % req.status_code)
            LOG.error(msg)
            return None

    def refresh_token(self):
        """Refresh the APIC token."""
        while True:
            time.sleep(self.token_expiry_time)
            LOG.debug("Refreshing APIC token...")

            path = '/api/aaaRefresh.json'

            try:
                req = requests.get(self.url(path), cookies=self.cookies, verify=False)
            except requests.exceptions.RequestException as ex:
                LOG.error("Token refresh failed: %s" % ex)
                return None

            if req.status_code == 200:
                resp = json.loads(req.text)
                token = resp['imdata'][0]['aaaLogin']['attributes']['token']
                self.cookies = {'APIC-Cookie': token}
                LOG.debug("Token refreshed successfully.")
            else:
                msg = "Token refresh failed with status code = %s" % req.status_code
                LOG.error(msg)
                return None

    def start_refresh_thread(self):
        """Start the token refresh thread."""
        refresh_thread = threading.Thread(target=self.refresh_token)
        refresh_thread.daemon = True
        refresh_thread.start()

    def get(self, path):
        """Get request.

        :param path: get url
        """
        try:
            req = requests.get(self.url(path), cookies=self.cookies,
                               verify=False)
        except requests.exceptions.RequestException as ex:
            msg = ("Exception occured while using get "
                   "requests, Reason %s" % ex)
            LOG.error(msg)
            return None
        if req.status_code == 200:
            resp = req.json()
            return resp
        else:
            msg = ("Get request failed with status code = %s"
                   % req.status_code)
            LOG.error(msg)
            return None

    def post(self, path, data):
        """Post request.

        :param path: get url
        :param data: url body
        """
        try:
            response = requests.post(self.url(path), data=data,
                                 cookies=self.cookies, verify=False)
        except requests.exceptions.RequestException as ex:
            msg = ("Exception occured while using post"
                   " requests, Reason %s" % ex)
            LOG.error(msg)
            return None

        if response.status_code == 200:
            return response.status_code

        else:
            msg = ("Post request failed with status code = %s"
                   % response.status_code)
            LOG.error(msg)
            return None

    def get_tenant(self, tenant, subtree=True):
        """Get the Tenant details.

        tenant:  Name of the tenant
        subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s.json' % tenant
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting tenant details of: %s" % tenant)

        tenant_details = self.get(path)
        return tenant_details

    def get_l3out(self, l3out, tenant, subtree=True):
        """Get the l3out details.

        :param l3out: String containing the name of L3Out
        :param tenant:  Name of the tenant
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/out-%s.json' % (tenant, l3out)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting l3out-%s details of tenant %s" % (l3out, tenant))

        l3out_details = self.get(path)
        return l3out_details

    def get_l3out_ext_instance_profile(self, l3out, ext_instance_profile,
                                       tenant, subtree=True):
        """Get the l3out external instance profile details.

        :param l3out: String containing the name of L3Out
        :param ext_instance_profile: External network instance profile name
        :param tenant:  Name of the tenant
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/out-%s/instP-%s.json' % (tenant,
                                                          l3out,
                                                          ext_instance_profile)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting external instance of l3out-%s details"
                 " of tenant-%s" % (l3out, tenant))

        l3out_details = self.get(path)
        return l3out_details

    def get_epg(self, epg, appprofile, tenant, subtree=True):
        """Get the EPG details.

        :param epg: String containing the name of EPG
        :param appprofile: String containing the name of Application Profile
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/ap-%s/epg-%s.json' % (tenant,
                                                       appprofile,
                                                       epg)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'
        LOG.info("Getting details of epg-%s of tenant-%s"
                 % (epg, tenant))

        epg_details = self.get(path)
        return epg_details

    def get_bd(self, bd, tenant, subtree=True):
        """Get the Bridge Domain details.

        :param bd: String containing the name of bride domain
        :param tenant:  Name of the tenant
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/BD-%s.json' % (tenant, bd)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of bd-%s of tenant-%s" % (bd, tenant))
        bd_details = self.get(path)
        return bd_details

    def get_context(self, context, tenant, subtree=True):
        """Get the private layer 3 network context .

        :param bd: String containing the name of context
        :param tenant:  Name of the tenant
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/ctx-%s.json' % (tenant, context)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of context-%s of tenant-%s"
                 % (context, tenant))

        context_details = self.get(path)
        return context_details

    def get_contract(self, contract, tenant, subtree=True):
        """Get the Contract details.

        :param contract: String containing the name of contract
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/brc-%s.json' % (tenant, contract)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of contract-%s of tenant-%s"
                 % (contract, tenant))

        contract_details = self.get(path)
        return contract_details

    def get_filter(self, filter_name, tenant, subtree=True):
        """Get the Tenant details.

        :param filter_name: String containing the name of filter
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/flt-%s.json' % (tenant, filter_name)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of filter-%s of tenant-%s"
                 % (filter_name, tenant))
        filter_details = self.get(path)
        return filter_details

    def get_filter_entry(self, filter_name, filt_entry, tenant, subtree=True):
        """Get the Filter Entry details.

        :param filter_name: String containing the name of filter
        :param filt_entry : Filter entry name
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/flt-%s/e-%s.json' % (tenant,
                                                      filter_name,
                                                      filt_entry)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of filter entry-%s "
                 " of filter-%s and tenant-%s" % (filt_entry,
                                                  filter_name,
                                                  tenant))
        filter_details = self.get(path)
        return filter_details

    def get_selection_policies(self, tenant, contract_name, graph_name,
                               node_name, subtree=True):
        """Get the selection policies details.

        :param tenant:  Name of the tenant
        :param contract_name: String containing the name of contract
        :param graph_name: String containing the name of graph
        :param node_name: String containing the name of node
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/ldevCtx-c-%s-g-%s-n-%s.json' % (
            tenant, contract_name, graph_name, node_name)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of selection policy-c-%s-g-%s-n-%s"
                 " for tenant-%s" % (contract_name, graph_name,
                                     node_name, tenant))

        selection_policies_details = self.get(path)
        return selection_policies_details

    def get_device(self, device_name, tenant, subtree=True):
        """Get the Device details.

        :param device_name: String containing the name of device
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/lDevVip-%s.json' % (tenant, device_name)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of device-%s of tenant-%s"
                 % (device_name, tenant))
        device_details = self.get(path)
        return device_details

    def get_abstract_graph(self, graph, tenant, subtree=True):
        """Get the Abstract Graph details.

        :param graph: The name of abstract graph
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/AbsGraph-%s.json' % (tenant, graph)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of abstract graph-%s of tenant-%s"
                 % (graph, tenant))
        abs_graph_details = self.get(path)
        return abs_graph_details

    def clone_abstract_graph(self, graph, source_graph, tenant):
        """Clone the Abstract Graph from given source graph template.

        :param graph: The name of abstract graph
        :param source_graph: The name of source graph to clone
        :param tenant:  Name of the tenant
        """
        path = base_url + 'tn-%s/AbsGraph-%s.json' % (tenant, graph)
        status = "created,modified"
        dn = "uni/tn-%s/AbsGraph-%s" % (tenant, graph)
        data = '{"vnsAbsGraph":{"attributes":{"dn": "%s", "name":"%s","status":"%s", "rn":"AbsGraph-%s"},\
        "children":[{"vnsAbsConnection":{"attributes":{"dn":"%s/AbsConnection-C1", "name":"C1",\
        "adjType":"L3","status":"%s","rn":"AbsConnection-C1"},\
        "children":[{"vnsRsAbsConnectionConns":{"attributes":{"tDn":"%s/AbsTermNodeCon-T1/AbsTConn",\
        "status":"%s"},"children":[]}},{"vnsRsAbsConnectionConns":{"attributes":\
        {"tDn":"%s/AbsNode-loadbalancer/AbsFConn-consumer","status":"%s"},"children":[]}}]}},\
        {"vnsAbsConnection":{"attributes": {"dn":"%s/AbsConnection-C2",\
        "name":"C2","adjType":"L3","status":"%s","rn":"AbsConnection-C2"},\
        "children":[{"vnsRsAbsConnectionConns":{"attributes":\
            {"tDn":"%s/AbsNode-loadbalancer/AbsFConn-provider","status":"%s"},"children":[]}},\
        {"vnsRsAbsConnectionConns":{"attributes":{"tDn":"%s/AbsTermNodeProv-T2/AbsTConn","status":"%s"},"children":[]}}]}},\
        {"vnsAbsNode":{"attributes":{"dn":"%s/AbsNode-loadbalancer",\
        "name":"loadbalancer","managed":"false","status":"%s","routingMode":"Redirect",\
        "rn":"AbsNode-loadbalancer"},"children":[{"vnsAbsFuncConn":{"attributes":\
        {"dn":"%s/AbsNode-loadbalancer/AbsFConn-consumer","name":"consumer",\
        "status":"%s","rn":"AbsFConn-consumer"},"children":[]}},{"vnsAbsFuncConn":{"attributes":\
        {"dn":"%s/AbsNode-loadbalancer/AbsFConn-provider","name":"provider",\
        "status":"%s","rn":"AbsFConn-provider"},"children":[]}},{"vnsRsNodeToLDev":\
        {"attributes":{"tDn":"uni/tn-common/lDevVip-%s","status":"%s"},\
        "children":[]}}]}},{"vnsAbsTermNodeCon":{"attributes":\
        {"dn":"%s/AbsTermNodeCon-T1","name":"T1","status":"%s","rn":"AbsTermNodeCon-T1"},\
        "children":[{"vnsAbsTermConn":{"attributes":\
        {"dn":"%s/AbsTermNodeCon-T1/AbsTConn","name":"1",\
        "status":"%s","rn":"AbsTConn"},"children":[]}}]}},\
        {"vnsAbsTermNodeProv":{"attributes":{"dn":"%s/AbsTermNodeProv-T2",\
        "name":"T2","status":"%s","rn":"AbsTermNodeProv-T2"},\
        "children":[{"vnsAbsTermConn":{"attributes":\
        {"dn":"%s/AbsTermNodeProv-T2/AbsTConn",\
        "name":"1","status":"%s","rn":"AbsTConn"},"children":[]}}]}}]}}' % (dn, graph, status, graph, dn, status, dn, status, dn, status, dn, status, dn, status, dn, status,
         dn, status, dn, status, dn, status, source_graph, status, dn, status, dn, status, dn, status, dn, status)
        self.post(path, data)
       
    def del_abstract_graph(self, graph, tenant):
        '''
        Delete Service Graph Template
        Args:
        graph(str): service graph name
        tenant(str): tenant name
        '''
        LOG.info("Deleting abstract graph-%s of tenant-%s" % (graph, tenant))
        path = base_url + 'tn-%s/AbsGraph-%s.json' % (tenant, graph)
        dn = "uni/tn-%s/AbsGraph-%s" % (tenant, graph)
        data = '{"vnsAbsGraph":{"attributes":{"dn":"uni/tn-%s/AbsGraph-%s","status":"deleted"},"children":[]}}' \
            % (tenant, graph)
        self.post(path, data)
          
    def set_service_graph_used_for_contract(self, graph, contract, tenant):
        '''
        Set L4-L7 Service Graph Template for contract
        Args:
        graph(str): service graph name
        tenant(str): tenant name
        contract(str): contract name
        '''
        path = base_url + 'tn-%s/brc-%s/subj-loadbalancedservice/rsSubjGraphAtt.json' % (tenant, contract) 
        data = '{"vzRsSubjGraphAtt":{"attributes":{"tnVnsAbsGraphName":"%s"},"children":[]}}' % (graph)
        LOG.info("Updating contract %s to use %s " % (contract, graph))
        graph_details = self.post(path, data)

    def get_service_graph_used_for_contract(self, contract, tenant):
        '''
        Gets the Service Graph Temple used for contractn
        Args:
        contract(str): contract name
        tenant(str): tenant name
        '''
        contract_subject = "loadbalancedservice"
        path = base_url + 'tn-%s/brc-%s/subj-%s/rsSubjGraphAtt.json' % (tenant, contract, contract_subject) 
        graph_details = self.get(path)
        return graph_details

    def get_service_graph_instance(self, abs_graph, tenant,
                                   contract, snat_policy_for_service=False,
                                   context="uni",
                                   subtree=True):
        """Get the Service Graph Instance details.

        :param graph: The name of abstract graph
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        ctrctDn = "uni/tn-%s/brc-%s" % (tenant, contract)
        graphDn = "uni/tn-%s/AbsGraph-%s" % (tenant, abs_graph)

        if snat_policy_for_service:
            scopeDn = "uni/tn-%s/ctx-%s" % (tenant, context)
        else:
            scopeDn = context

        path = base_url + 'tn-%s/GraphInst_C-[%s]-G-[%s]-S-[%s].json' % (
                tenant, ctrctDn, graphDn, scopeDn)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of service graph instance-"
                 "C-[%s]-G-[%s]-S-[%s] of tenant-%s"
                 % (ctrctDn, graphDn, scopeDn, tenant))
        svc_graph_instance_details = self.get(path)
        return svc_graph_instance_details

    def get_service_redirect_policy(self, policy, tenant, subtree=True):
        """Get the service redirect policy details.

        :param policy: String containing the name of redirect policy
        :param tenant:  Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/svcCont/svcRedirectPol-%s.json' % (
            tenant, policy)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of service redirect policy-%s"
                 " of tenant-%s" % (policy, tenant))

        redirect_policies_details = self.get(path)
        return redirect_policies_details

    def get_vlan_pool(self, vlan_pool, allocation_mode, tenant,
                      subtree=True):
        """Get the vlan pool details.

        :param vlan_pool: Name of the vlan pool
        :param allocation_mode: Allocation mode of the vlan pool
        :param tenant: Name of the tenant
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """

        path = base_url + 'infra/vlanns-[%s-%s]-%s.json' % (
            tenant, vlan_pool, allocation_mode)

        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of vlan pool vlanns-[%s-%s]-%s" %
                 (tenant, vlan_pool, allocation_mode))

        vlan_pool = self.get(path)
        return vlan_pool

    def get_vlan_encapsulation_block(self, vlan_pool, allocation_mode,
                                     tenant, vlan_from, vlan_to, subtree=True):
        """Get the vlan encapsulation block details.

        :param vlan_pool: Name of the vlan pool
        :param allocation_mode: Allocation mode of the vlan pool
        :param tenant: Name of the tenant
        :param vlan_from: The start of the vlan encapsulation block
        :param vlan_to: The end of the vlan encapsulation block
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """

        path = base_url + 'infra/vlanns-[%s-%s]-%s/from-[vlan-%s]-to-[vlan-%s].json' % (
            tenant, vlan_pool, allocation_mode, vlan_from, vlan_to)

        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        LOG.info("Getting details of vlan encapsulation block from-[vlan-%s]-to-[vlan-%s] of "
                 "vlan pool vlanns-[%s-%s]-%s" % (vlan_from, vlan_to, tenant, vlan_pool, allocation_mode))

        vlan_encapsulation_block = self.get(path)

        return vlan_encapsulation_block

    def get_hpp_hostprotRemoteIp(self, dn):
        path = '/api/node/mo/' + '%s.json?query-target=subtree&target-subtree-class=hostprotRemoteIp' % (dn) 
        hpp_policies_details = self.get(path)
        return hpp_policies_details

    def get_opflexODev_for_host(self, host_name):
        '''
        Gets opflex device details for a host
        Args:
        host_name(str): host name
        '''
        path = '/api/node/class/opflexODev.json?query-target-filter=and(eq(opflexODev.hostName,"%s"))'% host_name

        LOG.debug("Getting details of opflex device for host %s" % host_name)
        opflex_device_details = self.get(path)
        return opflex_device_details
    
    def get_opflexODev_for_mac(self, mac):
        '''
        Gets opflex device details with MAC address
        Args:
        mac(str): MAC address of Host/VM
        '''
        mac = mac.upper()
        path = '/api/node/class/opflexODev.json?query-target-filter=and(eq(opflexODev.mac,"%s"))'% mac

        LOG.debug("Getting details of opflex device for MAC %s" % mac)
        opflex_device_details = self.get(path)
        return opflex_device_details

    def get_vnsRsCIfPathAtt_for_host(self, host_name):
        '''
        Gets vnsRsCIfPathAtt details for a host
        Args:
        host_name(str): host name
        '''
        path = '/api/node/class/vnsRsCIfPathAtt.json?query-target-filter=and(wcard(vnsRsCIfPathAtt.dn,"%s"))'% host_name
        LOG.debug("Getting details of vnsRsCIfPathAtt for host %s" % host_name)
        vnsRsCIfPathAtt_details = self.get(path)
        return vnsRsCIfPathAtt_details

    def get_l3out_epg(self, l3out, tenant, l3out_epg_name, subtree=False):
        """Get the L3Out EPG details.

        :param l3out: String containing the name of L3Out
        :param tenant:  Name of the tenant
        :param l3out_epg_name: String containing the name of L3Out EPG
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/out-%s/instP-%s.json' % (tenant, l3out, l3out_epg_name)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        details = self.get(path)
        return details


    def get_vrf(self, vrf_name, tenant, subtree=True):
        """Get the VRF details.

        :param vrf_name: String containing the name of VRF
        :param tenant:  Name of the tenant
        :subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/ctx-%s.json' % (tenant, vrf_name)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        vrf_details = self.get(path)
        return vrf_details


    def get_ap(self, tenant, ap, subtree=True):
        """Get the Application Profile details.

        :param tenant:  Name of the tenant
        :param ap: String containing the name of Application Profile
        :param subtree: True/False, If True then it returns
                 all children details else only self details.
        """
        path = base_url + 'tn-%s/ap-%s.json' % (tenant, ap)
        if subtree:
            path = path + '?query-target=children'
        else:
            path = path + '?query-target=self'

        details = self.get(path)
        return details


    def get_bd_detail(self, tenant, bd):
        """Get the Bridge Domain details.

        :param tenant:  Name of the tenant
        :param bd: String containing the name of bride domain
        """
        bd_details = self.get_bd(bd, tenant, subtree=True)
        subnets_addr_list = list()
        for data in bd_details['imdata']:
            if data.get("fvSubnet", False):
                ip = data["fvSubnet"]["attributes"]["ip"]
                subnets_addr_list.append(ip)

        LOG.info(subnets_addr_list)
        return {
            'name': bd,
            'subnets_addr_list': subnets_addr_list
        }


    def get_bds(self, tenant):
        """Get the List of Bridge Domain for tenant.

        :param tenant:  Name of the tenant
        """
        aci_tenant = self.get_tenant(tenant, subtree=True)
        bds = []
        for data in aci_tenant['imdata']:
            if data.get("fvBD", False):
                bd = data["fvBD"]["attributes"]["name"]
                bds.append(bd)
        LOG.debug(bds)
        return bds

    def create_epg(self, tenant, ap, epg_name, source_epg):
        """ Creaete an epg given tenant and application profile.

        :param tenant: Name of the tenant
        :param ap: String containing the name of Application Profile
        :param epg_name: Name of the epg to be created
        :param source_epg: Source epg to get bd and vmm
        """

        path = base_url + 'tn-%s/ap-%s/epg-%s.json' % (tenant, ap, epg_name)
        bridge_domain = None
        vmm = None

        epg_details = self.get_epg(source_epg, ap, tenant)
        for mo in epg_details['imdata']:
            if 'fvRsBd' in mo:
                bridge_domain =  mo['fvRsBd']['attributes']['tnFvBDName']
            if 'fvRsDomAtt' in mo:
                vmm = mo['fvRsDomAtt']['attributes']['tDn']

        data = '{"fvAEPg": {"attributes": {"name": "%s"}, "children": [{"fvRsBd": {"attributes": {"tnFvBDName": "%s"}}}, {"fvRsDomAtt": {"attributes": {"resImedcy": "immediate", "tDn": "%s"}}}]}}' % (epg_name, bridge_domain, vmm)

        LOG.info(f"Creating EPG %s", epg_name)
        self.post(path, data)

    def delete_epg(self, tenant, ap, epg_name):
        """ Delete an epg given tenant and application profile.

        :param tenant: Name of the tenant
        :param ap: String containing the name of Application Profile
        :param epg_name: Name of the epg to be deleted
        """

        path = base_url + 'tn-%s/ap-%s/epg-%s.json' % (tenant, ap, epg_name)
        bridge_domain = None
        vmm = None

        epg_details = self.get_epg(epg_name, ap, tenant)
        for mo in epg_details['imdata']:
            if 'fvRsBd' in mo:
                bridge_domain =  mo['fvRsBd']['attributes']['tnFvBDName']
            if 'fvRsDomAtt' in mo:
                vmm = mo['fvRsDomAtt']['attributes']['tDn']

        data = '{"fvAEPg": {"attributes": {"name": "%s", "status": "deleted"}, "children": [{"fvRsBd": {"attributes": {"tnFvBDName": "%s"}}}, {"fvRsDomAtt": {"attributes": {"resImedcy": "immediate", "tDn": "%s"}}}]}}' % (epg_name, bridge_domain, vmm)

        LOG.info(f"Deleting EPG %s", epg_name)
        self.post(path, data)

    def get_total_mo_count(self, tenant):
        """Get the total number of managed objects for a tenant.

        :param tenant:  Name of the tenant
        """
        path = base_url + 'tn-%s.json' % tenant + '?query-target=subtree&rsp-subtree-include=count'
        data = self.get(path)
        count = int(data.get("imdata", [{}])[0].get("moCount", {}).get("attributes", {}).get("count", 0))
        return count

    def get_hpp_mo_count(self, tenant):
        """Get the total number of HostprotPol objects for a tenant.

        :param tenant:  Name of the tenant
        """
        path = base_url + 'tn-%s.json?query-target=subtree&target-subtree-class=hostprotPol' % tenant
        data = self.get(path)
        count = data.get('totalCount', 0)
        return count
