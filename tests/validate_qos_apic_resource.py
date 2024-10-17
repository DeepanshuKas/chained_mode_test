import os
from tests.apic_apis import ApicApi

from acc_pyutils import logger
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
from tests import lib_helper

LOG = logger.get_logger(__name__)
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')

def test_apic(qospolicy_name, namespace, pri, pbi, pre, pbe, dscpmark):

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    system_id = apic_provision['aci_config']['system_id']
    try:
        aci = ApicApi(apic_host, APIC_USERNAME, APIC_PASSWORD)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))
    path = "/api/mo/uni/tn-" + system_id
    qp_dn_format =  "/qosreq-" + system_id + "_qp_" + namespace + "_" + qospolicy_name
    qr_url =  path + qp_dn_format + ".json"
    qr_resp = aci.get(qr_url)
    assert int(qr_resp['totalCount']) != 0, "Failed to push QosRequirement Mo to APIC"
    if pri != 0 and pbi != 0:
        rsingress_url = path + qp_dn_format + "/rsingressDppPol.json"
        rsingress_resp = aci.get(rsingress_url)
        assert int(rsingress_resp['totalCount']) != 0, "Failed to push QosRsIngressDppPol Mo to APIC"
    if pre != 0 and pbe != 0:
        rsegress_url = path + qp_dn_format + "/rsegressDppPol.json"
        rsegress_resp = aci.get(rsegress_url)
        assert int(rsegress_resp['totalCount']) != 0, "Failed to push QosRsEgressDppPol Mo to APIC"
    if dscpmark != 0:
        dscpmark_url = path + qp_dn_format + "/dscp_marking.json"
        dscpmark_resp = aci.get(dscpmark_url)
        assert int(dscpmark_resp['totalCount']) != 0, "Failed to push qosEpDscpMarking Mo to APIC"
    
