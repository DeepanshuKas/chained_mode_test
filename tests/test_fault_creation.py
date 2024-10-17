import pytest
import os
import subprocess

from acc_pyutils.api import KubeAPI
from acc_pyutils import exceptions as kctlexc, logger, utils
from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from tests import lib, lib_helper, validate_fault_creation
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
ANNOTATE_STR = '{"tenant":"tenant_test","app-profile":"app-profile_test","name":"EPG_test"}'

@pytest.mark.skipif(APIC_VERSION < "5.2", reason="test is not functional in APIC versions < 5.2")
def test_pod_annotation_with_invalid_epg(base_fixture):

    pod = lib.create_resource('{}/busybox_annotate.yaml'.format(
        DATA_DIR), base_fixture)
    pod_name = pod['name']
    pod_namespace = pod['namespace']


    cmd_1 = ("kubectl annotate --namespace={} pod {} opflex.cisco.com/endpoint-group={}"
          "".format(pod_namespace,pod_name,ANNOTATE_STR))
    lib.exec_cmd(cmd_1)

    if APIC_VALIDATION:
        validate_fault_creation.test_apic(pod)

    cmd_2 = ("kubectl get pod {} -o yaml"
            "".format(pod_name))
    lib.exec_cmd(cmd_2)

@pytest.mark.skipif(APIC_VERSION < "5.2", reason="test is not functional in APIC versions < 5.2")
def test_deployment_annotation_with_invalid_epg(base_fixture):

    deployment = lib.create_resource('{}/deployment_annotate.yaml'.format(
        DATA_DIR), base_fixture)
    deployment_name = deployment['name']
    deployment_namespace = deployment['namespace']


    cmd_1 = ("kubectl annotate --namespace={} deployment {} opflex.cisco.com/endpoint-group={}"
          "".format(deployment_namespace,deployment_name,ANNOTATE_STR))
    lib.exec_cmd(cmd_1)

    if APIC_VALIDATION:
        validate_fault_creation.test_apic(deployment)

    cmd_2 = ("kubectl get deployment {} -o yaml"
            "".format(deployment_name))
    lib.exec_cmd(cmd_2)

@pytest.mark.skipif(APIC_VERSION < "5.2", reason="test is not functional in APIC versions < 5.2")
def test_ns_annotation_with_invalid_epg(base_fixture):

    namespace_obj = lib.create_resource('{}/namespace_annotate.yaml'.format(
        DATA_DIR), base_fixture)
    namespace = namespace_obj['name']


    cmd_1 = ("kubectl annotate --namespace={} namespace {} opflex.cisco.com/endpoint-group={}"
          "".format(namespace,namespace,ANNOTATE_STR))
    lib.exec_cmd(cmd_1)
    #subprocess.check_output(cmd, shell=True)

    if APIC_VALIDATION:
        validate_fault_creation.test_apic(namespace_obj)

    cmd_2 = "kubectl get namespace %s -o yaml" % namespace
    lib.exec_cmd(cmd_2)



