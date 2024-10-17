# this module has apic api implmentaion using acitoolkit
from acc_pyutils import logger
from acitoolkit import acitoolkit as aci
from tests import errors
from tests.input import cfg
from tests.endpoint import EndpointNew


LOG = logger.get_logger(__name__)
# Monkey patch acitoolkit to return the event
# with life cycle and contName set.
aci.Endpoint.get_all_by_epg = EndpointNew.get_all_by_epg


def aci_filter(aci_list, name):
    """Return specific aci object from given aci object list."""
    for aci_object in aci_list:
        if aci_object.name == name:
            return aci_object


class APIC(object):
    """it conatins apic apis implemented using acitookit."""

    def __init__(self, apic_ip, username, password):
        self.session = aci.Session('https://' + apic_ip, username, password)
        response = self.session.login()
        if not response.ok:
            raise errors.APICError('Could not log in to APIC.')

    def push_to_apic(self, tenant):
        """push config to apic."""
        response = tenant.push_to_apic(self.session)
        return True if response.ok else False

    def get_tenant(self, name):
        """Get the Tenant object.

        name:  Name of the tenant
        """
        return aci_filter(aci.Tenant.get_deep(self.session), name)

    def create_tenant(self, name):
        """Create Tenant.

        name:  Name of the tenant
        """
        tenant = aci.Tenant(name)
        self.push_to_apic(tenant)
        return tenant

    def delete_tenant(self, name):
        """Delete the Tenant.

        name:  Name of the tenant
        """
        tenant = self.get_tenant(name)
        tenant.mark_as_deleted()
        self.push_to_apic(tenant)

    def create_application_profile(self, name, tenant):
        """Create the Application Profile.

        name:   Name of the Application Profile
        tenant: Name of the tenant
        """
        tenant = self.get_tenant(tenant)
        appprofile = aci.AppProfile(name, tenant)
        self.push_to_apic(tenant)
        return appprofile

    def get_appprofile(self, tenant_name, ap_name=None):
        """Get All or specific App Profile object from provided tenant."""
        tenant = self.get_tenant(tenant_name)
        if ap_name:
            appprofile = aci_filter(
                aci.AppProfile.get(self.session, tenant), ap_name)
        else:
            appprofile = aci.AppProfile.get(self.session, tenant)
        return appprofile

    def get_l3out(self, tenant_name, l3out_name=None):
        """Get All or specific l3out object from provided tenant."""
        tenant = self.get_tenant(tenant_name)
        if l3out_name:
            l3out = aci_filter(
                aci.OutsideL3.get(self.session, tenant), l3out_name)
        else:
            l3out = aci.OutsideL3.get(self.session, tenant)

        # context = self.get_context_from_l3out(l3out)
        return l3out

    def create_l3out(self, l3out_name, tenant_name):
        """Create l3out."""
        tenant = self.get_tenant(tenant_name)
        l3out = aci.OutsideL3(l3out_name, tenant)
        return l3out

    def add_context_to_l3out(self, l3out, context):
        """Add context to the L3out.

        :param context: Instance of Context class to assign to this
                        OutsideL3.
        """
        l3out.add_context(context)

    def remove_context_from_l3out(self, l3out, context):
        """Remove context from the L3out.

        :param context: Instance of Context class to remove from this
                        OutsideL3.
        """
        l3out.remove_context(context)

    @staticmethod
    def get_context_from_l3out(l3out):
        """Return the assigned context.

        :returns: Instance of Context class that this OutsideL3 is assigned.
                  If no Context is assigned, None is returned.
        """
        return l3out.get_context()

    def delete_appprofile(self, ap_name, tenant_name):
        """Delete Application Profile."""
        tenant = self.get_tenant(tenant_name)
        ap = aci_filter(self.get_appprofile(tenant_name), ap_name)
        ap.mark_as_deleted()
        self.push_to_apic(tenant)

    def create_context(self, name, tenant):
        """Create the context.

        name:   Name of the Context
        tenant: Name of the tenant
        """
        tenant = self.get_tenant(tenant)
        context = aci.Context(name, tenant)
        self.push_to_apic(tenant)
        return context

    def get_context(self, tenant_name):
        tenant = self.get_tenant(tenant_name)
        return aci.Context.get(self.session, tenant)

    def delete_context(self, context_name, tenant_name):
        tenant = self.get_tenant(tenant_name)
        context = aci_filter(self.get_context(tenant_name), context_name)
        context.mark_as_deleted()
        self.push_to_apic(tenant)

    def set_subnet_scope(self, subnet, scope):
        """Set subnet scope.

        :param:subnet  Instance of subnet.
        :param:scope   Scope to be set for given subnet.
        :return:
        """
        tenant = subnet.get_parent().get_parent()
        subnet.set_scope(scope)
        self.push_to_apic(tenant)

    def get_outside_l3(self, l3out_name, tenant_name):
        """Return instance of given l3out.

        :param:l3out_name  The name of the l3out.
        :param:tenant_name The name of the tenant.
        :return: OutsideL3 Instance.
        """
        tenant = self.get_tenant(tenant_name)
        return aci_filter(tenant.get_children(only_class=aci.OutsideL3),
                          l3out_name)

    def get_outside_epg_for_l3out(self, l3out_name, outside_epg, tenant_name):
        """Return outside epg instance of given l3out.

        :param:l3out_name  The name of the l3out.
        :param:outside_epg  The name of the outside_epg.
        :param:tenant_name The name of the tenant.
        :return: OutsideEPG Instance.
        """
        l3out_inst = self.get_outside_l3(l3out_name, tenant_name)
        return self.get_outside_epg(l3out_inst, outside_epg)

    @staticmethod
    def get_outside_epg(l3out, outside_epg):
        """Get Outside EPG from given l3out.

        :param:l3out       Instance of l3out.
        :param:outside_epg The Name of the Outside EPG.
        :return: Outside EPG instance.
        """
        return aci_filter(l3out.get_children(), outside_epg)

    @staticmethod
    def get_ext_subnets(outside_epg):
        """Get all of the external subnets from given Outside EPG.

        :param:outside_epg Instance of Outside EPG.
        :return: List of External Subnets.
        """
        return outside_epg.get_children(only_class=aci.OutsideNetwork)

    def set_scope_for_ext_subnet(self, l3out_name, outside_epg,
                                 tenant_name, scope, name='', ip=''):
        """Set scope for external subnet.

        :param: l3out_name Name of the l3out.
        :param: outside_epg Name of the outside epg.
        :param: tenant_name Name of the tenant.
        :param: scope scope to be set of ext subnet.
        :param: name name of the subnet(optional).
        :param: ip ip of the subnet(optional).
        :return:
        """
        l3out_inst = self.get_outside_l3(l3out_name, tenant_name)
        if not l3out_inst:
            assert False, 'l3out [%s] not found in tenant [%s]' % (l3out_name,
                                                                   tenant_name)

        outside_epg_inst = self.get_outside_epg(l3out_inst, outside_epg)
        if not outside_epg_inst:
            assert False, ('outside epg [%s] not found for l3out [%s]' % (
                outside_epg, l3out_name))

        ext_subnet_list = self.get_ext_subnets(outside_epg_inst)
        if not ext_subnet_list:
            assert False, ('subnet not found for outside epg [%s] '
                           'of l3out [%s]' % (outside_epg, l3out_name))

        ext_subnet_flag = False
        if len(ext_subnet_list) > 1:
            for ext_subnet in ext_subnet_list:
                if ((ext_subnet.name and ext_subnet.name == name) or
                        ext_subnet.ip == ip):
                    ext_subnet_flag = True
                    ext_subnet.set_scope(scope)
            if not ext_subnet_flag:
                assert False, ("ext subnet with name = [%s] or ip [%s] "
                               "not found for outside epg [%s] of "
                               " l3out [%s]" % (name, ip, outside_epg,
                                                l3out_name))
        else:
            ext_subnet_list[0].set_scope(scope)

        tenant = l3out_inst.get_parent()
        res = self.push_to_apic(tenant)
        assert res is True, ("Failed to set subnet scope for outside "
                             "epg [%s] of l3out [%s]" % (outside_epg,
                                                         l3out_name))

    def get_scope_for_ext_subnet(self, l3out_name, outside_epg,
                                 tenant_name, name='', ip=''):
        """Set scope for external subnet.

        :param: l3out_name Name of the l3out.
        :param: outside_epg Name of the outside epg.
        :param: tenant_name Name of the tenant.
        :param: name name of the subnet(optional).
        :param: ip ip of the subnet(optional).
        :return: scope of external subnet (with given ip or name)
                 if name and ip is not provided then default ext subnet
                 (if available) scope is return
        """
        l3out_inst = self.get_outside_l3(l3out_name, tenant_name)
        if not l3out_inst:
            assert False, 'l3out [%s] not found in tenant [%s]' % (l3out_name,
                                                                   tenant_name)

        outside_epg_inst = self.get_outside_epg(l3out_inst, outside_epg)
        if not outside_epg_inst:
            assert False, ('outside epg [%s] not found for l3out [%s]' % (
                outside_epg, l3out_name))

        ext_subnet_list = self.get_ext_subnets(outside_epg_inst)
        if not ext_subnet_list:
            assert False, ('subnet not found for outside epg [%s] '
                           'of l3out [%s]' % (outside_epg, l3out_name))

        ext_subnet_flag = False
        if len(ext_subnet_list) > 1:
            for ext_subnet in ext_subnet_list:
                if ((ext_subnet.name and ext_subnet.name == name) or
                        ext_subnet.ip == ip):
                    ext_subnet_flag = True
                    return ext_subnet.get_scope()
            if not ext_subnet_flag:
                assert False, ("ext subnet with name = [%s] or ip [%s] "
                               "not found for outside epg [%s] of "
                               " l3out [%s]" % (name, ip, outside_epg,
                                                l3out_name))
        else:
            return ext_subnet_list[0].get_scope()

    def get_epg(self, tenant, name, app_profile="kubernetes"):
        appprofile = aci_filter(tenant.get_children(only_class=aci.AppProfile),
                                app_profile)
        assert appprofile, ('ApplicationProfile[%s] not found in '
                            'tenant[%s]' % (app_profile, tenant.name))
        return aci_filter(
            appprofile.get_children(),
            name)

    def get_endpoints(self, tenant_name, app_name, epg_name, ep_name,
                      with_interface_attachments=False):
        """Get EPG Endpoint.

        :param: tenant_name Name of the tenant.
        :param: app_name Name of the application profile.
        :param: epg_name Name of the EPG.
        :param: ep_name Name of the endpoint.
        :return: Endpoint Instance.
        """
        aci_list = aci.Endpoint.get_all_by_epg(self.session, tenant_name,
                                               app_name, epg_name,
                                               with_interface_attachments)
        for aci_object in aci_list:
            if aci_object.contName == ep_name \
                    and aci_object.lcC == 'learned,vmm':
                return aci_object

    def get_bd_from_epg(self, epg):
        return epg.get_bd()

    def get_bd(self, bd_name, tenant_name):
        tenant = self.get_tenant(tenant_name)
        bd = aci_filter(aci.BridgeDomain.get(self.session, tenant), bd_name)
        return bd

    @staticmethod
    def add_tag(obj):
        """Tag to object."""
        return obj.add_tag()

    @staticmethod
    def delete_tag(obj):
        """Delete tag from object."""
        return obj.delete_tag()

    @staticmethod
    def remove_bd(epg):
        """Remove BridgeDomain from the EPG."""
        epg.remove_bd()

    @staticmethod
    def has_bd(epg):
        """Check if a BridgeDomain has been assigned to the EPG.

        :returns: True or False.  True if the EPG has been assigned
                  a BridgeDomain.
        """
        return epg.has_bd()

    def get_contract_from_tenant(self, tenant, name):
        return aci_filter(aci.Contract.get(self.session, tenant), name)

    def get_contract(self, tenant_name, contract_name=None):
        """Get All or specific contract object from provided tenant."""
        tenant = self.get_tenant(tenant_name)
        if contract_name:
            contract = aci_filter(
                aci.Contract.get(self.session, tenant), contract_name)
        else:
            contract = aci.Contract.get(self.session, tenant)
        resp = contract.subscribe(self.session,
                                  extension='&query-target=children')
        print(resp)
        return contract

    def get_all_providing_epgs(self, contract):
        """Get all of the EPGs providing this contract.

        :param:contract  instance of contract
        :return: List of EPG instances
        """
        return contract.get_all_providing_epgs()

    def get_all_consuming_epgs(self, contract):
        """Get all of the EPGs consuming this contract.

        :param:contract instance of  contract
        :return: List of EPG instances
        """
        return contract.get_all_consuming_epgs()

    def get_filter(self, tenant_name, filter_name=None):
        """Get All or specific filter object from provided tenant."""
        tenant = self.get_tenant(tenant_name)
        if filter_name:
            filter_inst = aci_filter(
                aci.Filter.get(self.session, tenant), filter_name)
        else:
            filter_inst = aci.Filter.get(self.session, tenant)

        return filter_inst

    def get_subnet(self, tenant_name, bd, subnet_name=None):
        """Get All or specific subnet object from provided tenant."""
        tenant = self.get_tenant(tenant_name)
        if subnet_name:
            subnet_inst = aci_filter(
                aci.Subnet.get(self.session, bd, tenant), subnet_name)
        else:
            subnet_inst = aci.Subnet.get(self.session, bd, tenant)

        return subnet_inst

    @staticmethod
    def get_contracts_from_epg(epg):
        return epg.get_all_provided(), epg.get_all_consumed()

    def consume(self, epg, contract):
        epg.consume(contract)
        tenant = epg.get_parent().get_parent()
        self.push_to_apic(tenant)

    def set_contract(self, epg, contract, tenant_name, l3out):
        """consume contract for outside epg."""
        epg.consume(contract)
        epg_url = "/api/node/mo/uni/tn-%s/out-%s/instP-%s.json" % (tenant_name,
                                                                   l3out,
                                                                   epg.name)
        res = self.session.push_to_apic(epg_url, epg.get_json())
        return res

    def unset_contract(self, epg, contract, tenant_name, l3out):
        """unset contract for outside epg."""
        epg.dont_consume(contract)
        epg_url = "/api/node/mo/uni/tn-%s/out-%s/instP-%s.json" % (tenant_name,
                                                                   l3out,
                                                                   epg.name)
        res = self.session.push_to_apic(epg_url, epg.get_json())
        return res

    def provide(self, epg, contract):
        epg.provide(contract)
        tenant = epg.get_parent().get_parent()
        self.push_to_apic(tenant)

    def dont_consume(self, epg, contract):
        epg.dont_consume(contract)
        tenant = epg.get_parent().get_parent()
        self.push_to_apic(tenant)

    def dont_provide(self, epg, contract):
        epg.dont_provide(contract)
        tenant = epg.get_parent().get_parent()
        self.push_to_apic(tenant)

    def set_contract_for_epg(self, tenant_name, epg_name,
                             contract_name, provider=False):
        """Set the contract for an EPG.

        By default EPGs are consumers of a contract.
        Set provider flag to True for the EPG to act as a provider.

        Arguments:
        tenant_name -- name of the tenant
        contract_name    -- name of the contract
        epg_name    -- name of the epg
        """
        tenant = self.get_tenant(tenant_name)
        epg = self.get_epg(tenant, epg_name)
        contract = self.get_contract_from_tenant(tenant, contract_name)
        if provider:
            self.provide(epg, contract)
        else:
            self.consume(epg, contract)
        self.push_to_apic(tenant)

    def unset_contract_for_epg(self, tenant_name, epg_name,
                               contract_name, provider=False):
        """Unset the contract for an EPG.

        Arguments:
        tenant_name -- name of the tenant
        contract_name    -- name of the contract
        epg_name    -- name of the epg
        """
        tenant = self.get_tenant(tenant_name)
        epg = self.get_epg(tenant, epg_name)
        contract = self.get_contract_from_tenant(tenant, contract_name)
        if provider:
            self.dont_provide(epg, contract)
        else:
            self.dont_consume(epg, contract)
        self.push_to_apic(tenant)

    def get_contract_info(self, tenant_name, epg_name):
        """Return contract info(both provided and consumed).

        tenant_name -- The name of Tenant
        epg_name     -- The name of EPG
        """
        contract_info = dict()
        tenant = self.get_tenant(tenant_name)
        epg = self.get_epg(tenant, epg_name)
        provided, consumed = self.get_contracts_from_epg(epg)
        contract_info['provided'] = list()
        for contract in provided:
            contract_info['provided'].append(contract.name)
        contract_info['consumed'] = list()
        for contract in consumed:
            contract_info['consumed'].append(contract.name)
        return contract_info

    def create_bd(self, bd_name, tenant_name,
                  address=None, scope="private",
                  vrf=None):
        """Create a BridgeDomain.

        bd_name     -- The name of BridgeDomain
        tenant_name -- The name of Tenant
        address -- 'Subnet IPv4 Address
        scope' -- 'The scope of subnet ("public", "private", "shared",
                    "public,shared", "private,shared",
                    "shared,public", "shared,private")')
        vrf    -- The name of VRF
        """
        tenant = self.get_tenant(tenant_name)
        # context = aci.Context('myvrf', tenant)
        bd = aci.BridgeDomain(bd_name, tenant)
        # bd.add_context(context)

        if vrf is not None:
            # vrf_obj = aci.Context(vrf)
            context = aci.Context(vrf, tenant)
            bd.add_context(context)

        if address is None:
            bd.set_arp_flood('yes')
            bd.set_unicast_route('no')
        else:
            bd.set_arp_flood('no')
            bd.set_unicast_route('yes')
            # bd.add_subnet(address)

            subnet = aci.Subnet('', bd)
            subnet.addr = address

            if scope is None:
                subnet.set_scope("private")
            else:
                subnet.set_scope(scope)

        self.push_to_apic(tenant)
        return bd

    def delete_bd(self, bd_name, tenant_name):
        """Delete a bridge domain."""
        tenant = self.get_tenant(tenant_name)
        bd = self.get_bd(bd_name, tenant_name)
        # delete bd context
        if bd.has_context():
            bd.remove_context()

        # delete all subnets ??
        # subnets = bd.get_subnets()
        # for subnet in subnets:
        #    bd.remove_subnet(subnet)

        bd.mark_as_deleted()
        self.push_to_apic(tenant)

    def delete_epg(self, epg):
        epg.mark_as_deleted()
        response = epg.get_parent().get_parent().push_to_apic(self.session)
        if not response.ok:
            LOG.error("Deletions failed for EPG [%s]" % epg.name)

    def get_vmm(self, name):
        return aci.VmmDomain.get_by_name(self.session, name)

    def create_epg(self, name, tenant, bd, vmm, app_profile="kubernetes"):
        appprofile = aci_filter(tenant.get_children(only_class=aci.AppProfile),
                                app_profile)
        epg = aci.EPG(name, appprofile)
        epg.add_bd(bd)
        epg.attach(vmm)
        response = tenant.push_to_apic(self.session)
        if not response.ok:
            assert False, ("EPG [%s] creation failed." % name)
        else:
            return epg

    def clone_kubernetes_epg(self, name, tenant, system_id,
                             source_epg_name='kube-default',
                             app_profile='kubernetes',
                             kube_naming_used=True,
                             contract=True):
        kube_tenant = self.get_tenant(tenant)
        source_epg = self.get_epg(kube_tenant, source_epg_name, app_profile)
        kube_bd = self.get_bd_from_epg(source_epg)
        kube_vmm = self.get_vmm(system_id)
        epg = self.create_epg(name, kube_tenant, kube_bd,
                              kube_vmm, app_profile)
        if contract:
            provided, consumed = self.get_contracts_from_epg(source_epg)
            if kube_naming_used:
                aci_prefix = system_id
            else:
                aci_prefix = cfg.ACI_PREFIX + '_' + system_id
            for contract in provided:
                if contract.name != '%s-l3out-allow-all' % aci_prefix:
                    self.provide(epg, contract)
            for contract in consumed:
                if contract.name != 'kube-api':
                    self.consume(epg, contract)
        LOG.info('CREATED EPG %s IN TENANT %s', name, tenant)
        return epg

    def create_contract(self, name, tenant):
        """Create the contract.

        :param name: The name of contract.
        :param tenant: tenant instance.
        :return: contract instance
        """
        contract = aci.Contract(name, tenant)
        res = self.push_to_apic(tenant)
        assert res is True, 'contract [%s] creations failed' % name
        return contract

    def create_filter_entry(self,  name, contract, tenant,
                            dToPort='unspecified',
                            applyToFrag='no',
                            arpOpc='unspecified',
                            dFromPort='unspecified',
                            etherT='ip',
                            prot='tcp',
                            sFromPort='unspecified',
                            sToPort='unspecified',
                            tcpRules='unspecified'):
        entry1 = aci.FilterEntry(name,
                                 applyToFrag=applyToFrag,
                                 arpOpc=arpOpc,
                                 dFromPort=dFromPort,
                                 dToPort=dToPort,
                                 etherT=etherT,
                                 prot=prot,
                                 sFromPort=sFromPort,
                                 sToPort=sToPort,
                                 tcpRules=tcpRules,
                                 parent=contract)
        if self.push_to_apic(tenant):
            return entry1
        else:
            LOG.error("Filter Entry [%s] creations failed." % name)

    def delete_contract(self, contract):
        """Delete the contract.

        :param contract: The contract instance
        :return:
        """
        contract.mark_as_deleted()
        response = contract.get_parent().push_to_apic(self.session)
        if not response.ok:
            LOG.error("Contract [%s] deletion failed." % contract.name)

    def delete_filter(self, name, tenant):
        """Delete Filter.

        :param name: The name of the filter.
        :param tenant: The instance of tenant.
        :return:
        """
        filt = aci_filter(aci.Filter.get(self.session, tenant), name)
        if filt:
            filt.mark_as_deleted()
            if not self.push_to_apic(tenant):
                LOG.error("Filter [%s] deletions failed." % name)
        else:
            LOG.error("Filter [%s] not found." % name)

    def delete_filter_entry(self, entry):
        """Delete Filter Entry.

        :param name: instance of filter entry.
        :return:
        """
        entry.mark_as_deleted()
        response = entry.get_parent().get_parent().push_to_apic(self.session)
        if not response.ok:
            LOG.error("Filter Entry [%s] deletions failed." % entry.name)
