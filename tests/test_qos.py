import os
import time

import pytest

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib, lib_helper, validate_qos_apic_resource
from tests.input.cfg import (APIC_VALIDATION,
                             APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)

APIC_PROVISION = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
ACI_CLIENT = lib_helper.APIC(
        user=APIC_USERNAME,
        passwd=APIC_PASSWORD,
        apic_ip=APIC_PROVISION['aci_config']['apic_hosts'][0])
DATA_DIR = os.path.abspath('tests/test_data')
LOG = logger.get_logger(__name__)
APIC_VERSION = ACI_CLIENT.get_apic_version()

INTERVAL = 15

# Ability to configure Qos Policy is available in APIC versions >= 5.1(x) only.
@pytest.mark.skipif(APIC_VERSION < "5.1", reason="test is not functional in APIC versions < 5.1(x)")
def test_qos_for_pod(base_fixture):
    lib.create_resource('{}/busybox_qos.yaml'.format(DATA_DIR), base_fixture)
    policy = lib.create_resource('{}/sample_qos_policy.yaml'.format(
        DATA_DIR), base_fixture)
    qos_policy = lib.get_detail(
        'QosPolicy', name=policy['name'], namespace=policy['namespace'])

    qospolicy_name = policy['name']
    namespace=policy['namespace']
    pri = lib.get_qos_ingress_policing_rate_from_file(qos_policy)
    pbi = lib.get_qos_ingress_policing_burst_from_file(qos_policy)
    pre = lib.get_qos_egress_policing_rate_from_file(qos_policy)
    pbe = lib.get_qos_egress_policing_burst_from_file(qos_policy)
    dscpmark = lib.get_qos_dscpmark_from_file(qos_policy)
    
    time.sleep(INTERVAL)

    if APIC_VALIDATION:
        validate_qos_apic_resource.test_apic(qospolicy_name, namespace, pri, pbi, pre, pbe, dscpmark)
    if True:
        kapi = KubeAPI()
        cmd = "kubectl get Qospolicy %s -o yaml" % qospolicy_name
        LOG.info("Cmd is: %s", cmd)
        try:
            exec_cli = kapi.exec_cli_cmd(cmd)
            print(exec_cli)
        except Exception as ex:
            LOG.error("policy creation failed with %s", ex)
