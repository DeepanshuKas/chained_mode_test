import os
import time

import pytest

from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests import lib, lib_helper, validate_erspan_apic_resource
from tests.input.cfg import (APIC_PROVISION_FILE, APIC_VALIDATION)
DATA_DIR = os.path.abspath('tests/test_data')
LOG = logger.get_logger(__name__)
INTERVAL = 50

def test_erspan_policy_by_labels(base_fixture):
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    domain_name = apic_provision['aci_config']['system_id']
    kapi = KubeAPI()
    lib.create_resource('{}/case_6_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    policy = lib.create_resource('{}/case_erspan_labels.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    erspanpolicy_name = policy['name']
    ceps = validate_erspan_apic_resource.erspan_client_end_points(policy)
    if APIC_VALIDATION:
        validate_erspan_apic_resource.test_apic(erspanpolicy_name, ceps, policy)

    try:
        exec_cli = kapi.get('ErspanPolicy', erspanpolicy_name)
    except Exception as ex:
        LOG.error("Erspan policy creation failed with %s", ex)
    time.sleep(INTERVAL)
    validate_erspan_apic_resource.check_mirror_in_ovs(domain_name, policy, erspanpolicy_name)

def test_erspan_policy_by_namespace(base_fixture):
    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    domain_name = apic_provision['aci_config']['system_id']
    kapi = KubeAPI()
    lib.create_resource('{}/case_6_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    policy = lib.create_resource('{}/case_erspan_ns.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    erspanpolicy_name = policy['name']

    ceps = validate_erspan_apic_resource.erspan_client_end_points(policy)
    if APIC_VALIDATION:
        validate_erspan_apic_resource.test_apic(erspanpolicy_name, ceps, policy)

    try:
        exec_cli = kapi.get('ErspanPolicy', erspanpolicy_name)
    except Exception as ex:
        LOG.error("Erspan policy creation failed with %s", ex)
    time.sleep(INTERVAL)
    validate_erspan_apic_resource.check_mirror_in_ovs(domain_name, policy, erspanpolicy_name)
