import os

from tests.apic_apis import ApicApi
from tests import lib_helper
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)

CONFIG_FILE = os.path.abspath('tests/input/cfg.py')
    
def test_apic(netflowpolicy_name):

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    domain_name = apic_provision['aci_config']['system_id']
    try:
        aci = ApicApi(apic_host, APIC_USERNAME, APIC_PASSWORD)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))
    aci_client = lib_helper.APIC(
        user=APIC_USERNAME,
        passwd=APIC_PASSWORD,
        apic_ip=apic_provision['aci_config']['apic_hosts'][0])
    vmmDomPObj =  aci_client.get_vmm_domain(domain_name)
    vmmDomPDn = vmmDomPObj['imdata'][0]['vmmDomP']['attributes']['dn']
    
    infra_path = "/api/mo/uni/infra"
    netflow_dn_format =  "/vmmexporterpol-" + domain_name + "_nfp_" + netflowpolicy_name
    netflow_url =  infra_path + netflow_dn_format + ".json"
    netflow_resp = aci.get(netflow_url)
    assert int(netflow_resp['totalCount']) != 0, "Failed to push netflowVmmExporterPol Mo to APIC"
    VmmVSwitch_path = "/api/mo/" + vmmDomPDn + "/vswitchpolcont"
    VmmVSwitch_url = VmmVSwitch_path  + ".json"
    VmmVSwitch_resp = aci.get(VmmVSwitch_url)
    assert int(netflow_resp['totalCount']) != 0, "Failed to push vmmVSwitchPolicyCont Mo to APIC"
    RsVmmVSwitch_dn_format = "/rsvswitchExporterPol-" + "[uni/infra/vmmexporterpol-" + domain_name + "_nfp_" + netflowpolicy_name + "]"
    RsVmmVSwitch_url = VmmVSwitch_path + RsVmmVSwitch_dn_format + ".json"
    RsVmmVSwitch_resp = aci.get(RsVmmVSwitch_url)
    assert int(netflow_resp['totalCount']) != 0, "Failed to push vmmRsVswitchExporterPol Mo to APIC"
