from acitoolkit.acibaseobject import BaseACIObject
from acitoolkit import acitoolkit as aci


class EndpointNew(BaseACIObject):
    @classmethod
    def get_all_by_epg(cls, session, tenant_name, app_name, epg_name,
                       with_interface_attachments=True):
        """Get all of the Endpoints for a specified EPG.

        :param session: Session instance used to communicate with the APIC.
                        Assumed to be logged in
        :param tenant_name: String containing the tenant name
        :param app_name: String containing the app name
        :param epg_name: String containing the epg name
        :param with_interface_attachments: Boolean indicating whether
                interfaces should be attached or not. True is default.
        :return: List of Endpoint instances
        """
        if with_interface_attachments:
            raise NotImplementedError
        query_url = ('/api/mo/uni/tn-%s/ap-%s/epg-%s.json?'
                     'rsp-subtree=children&'
                     'rsp-subtree-class=fvCEp,fvStCEp' % (tenant_name,
                                                          app_name,
                                                          epg_name))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        endpoints = []
        if len(data) == 0:
            return endpoints
        assert len(data) == 1
        assert 'fvAEPg' in data[0]
        if 'children' not in data[0]['fvAEPg']:
            return endpoints
        endpoints_data = data[0]['fvAEPg']['children']
        if len(endpoints_data) == 0:
            return endpoints
        tenant = aci.Tenant(tenant_name)
        app = aci.AppProfile(app_name, tenant)
        epg = aci.EPG(epg_name, app)
        for ep_data in endpoints_data:
            if 'fvStCEp' in ep_data:
                mac = ep_data['fvStCEp']['attributes']['mac']
                ip = ep_data['fvStCEp']['attributes']['ip']
            else:
                mac = ep_data['fvCEp']['attributes']['mac']
                ip = ep_data['fvCEp']['attributes'].get('ip')
                lcC = ep_data['fvCEp']['attributes']['lcC']
                contName = ep_data['fvCEp']['attributes']['contName']
            ep = cls(str(mac), epg)
            ep.mac = mac
            ep.ip = ip
            ep.lcC = lcC
            ep.contName = contName
            endpoints.append(ep)
        return endpoints
