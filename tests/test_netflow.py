import os

import pytest

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib, lib_helper, validate_netflow_apic_resource
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

# Ability to configure Netflow Policy is available in APIC versions >= 5.0(x) only.
@pytest.mark.skipif(APIC_VERSION < "5.0", reason="test is not functional in APIC versions < 5.0(x)")
def test_netflow_policy_on_cluster(base_fixture):

    policy = lib.create_resource('{}/sample_netflow_policy.yaml'.format(
        DATA_DIR), base_fixture)
    netflow_policy = lib.get_detail('NetflowPolicy', name=policy['name'])
    netflowpolicy_name = policy['name']
    
    if APIC_VALIDATION:
        validate_netflow_apic_resource.test_apic(netflowpolicy_name)

    kapi = KubeAPI()
    try:
        exec_cli = kapi.get('NetflowPolicy', netflowpolicy_name)
    except Exception as ex:
        LOG.error("Netflow policy creation failed with %s", ex)
