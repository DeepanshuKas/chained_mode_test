import os

from tests.apic_apis import ApicApi
from tests import lib_helper
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)

CONFIG_FILE = os.path.abspath('tests/input/cfg.py')

def test_apic(obj):
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    domain_name = apic_provision['aci_config']['system_id']
    comp_uni_path = "/api/node/mo/comp/"             
    ctrl_name = apic_provision['aci_config']['system_id']

    try:
        aci = ApicApi(apic_host, APIC_USERNAME, APIC_PASSWORD)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))
    aci_client = lib_helper.APIC(
                 user=APIC_USERNAME,
                 passwd=APIC_PASSWORD,
                 apic_ip=apic_provision['aci_config']['apic_hosts'][0])

        
    tmp_dn = ("{}prov-Kubernetes/ctrlr-[{}]-{}/injcont/info/clusterfaultinfo-"
                "".format(comp_uni_path,domain_name, ctrl_name))
    

    if (obj['kind'] == "Pod"):
        fault_dn = tmp_dn + "{}.json".format(10)
    elif (obj['kind'] == "Deployment"):
        fault_dn = tmp_dn + "{}.json".format(12)
    elif (obj['kind'] == "Namespace"):
        fault_dn = tmp_dn + "{}.json".format(11)
    

    api_resp = aci.get(fault_dn)
    
    assert int(api_resp['totalCount']) != 0, " Failed to push vmmClusterFaultInfo to APIC"
