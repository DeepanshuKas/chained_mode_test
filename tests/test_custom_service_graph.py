import os
import time
import pytest

from acc_pyutils import logger
from collections import OrderedDict
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
from tests import lib, lib_helper
from tests.template_utils import env
from tests.test_datapath import _get_input_for_svc_and_deployment, \
     _get_input_for_namespace

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')
# waiting time for service graph instance to change its state
POLL_TIMEOUT = 30

def annotate_svc_with_service_graph_name(svc_name, svc_ns="default", value="test"):
    cmd_1 = ("kubectl annotate --namespace={} service {} opflex.cisco.com/service-graph-name={}"
          "".format(svc_ns, svc_name, value))
    lib.exec_cmd(cmd_1)

def remove_annotate_svc_with_service_graph_name(svc_name, svc_ns="default"):
    cmd_1 = ("kubectl annotate --namespace={} service {} opflex.cisco.com/service-graph-name-"
          "".format(svc_ns, svc_name))
    lib.exec_cmd(cmd_1)

@pytest.mark.usefixtures("clean_gen_templates")
def test_custom_service_graph(base_fixture, gen_template_name):

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)

    config = {
        'apic_host': apic_provision['aci_config']['apic_hosts'][0],
        'apic_username': APIC_USERNAME,
        'apic_password': APIC_PASSWORD,
        'system_id': apic_provision['aci_config']['system_id'],
        'l3out': apic_provision['aci_config']['l3out']['name'],
        'ext_network': apic_provision['aci_config']['l3out']['external_networks'][0],
        'vrf_name': apic_provision['aci_config']['vrf']['name'],
    }

    try:
        apic = ValidateApi(config)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))

    # Check for global svc graph
    result = apic.is_global_service_graph_exist()
    assert result, ("Global Service Graph not Found. Cann't Start the test")

    # 1) Create Service Graph Template  
    custom_graph_name = "test_svc_graph"
    apic.create_custom_service_graph(custom_graph_name)
    result = apic.is_abstract_graph_exist(custom_graph_name)
    assert result, "Service Graph %s not Created.\
              Cann't Start the test " % (custom_graph_name)

    try:
        # 2) Create a Namespace, LB service and Service endpoint
        svc_name = "test-svc"
        svc_ns = "test-ns"
        selector = {'name': svc_name}
        test_svc = {'name': svc_name, 'namespace': svc_ns}
        deploy_in = {'name': 'nginx-deploy', 'namespace': svc_ns,
            'label': selector }
        ns = _get_input_for_namespace(svc_ns)
        deploy, svc = _get_input_for_svc_and_deployment(
            deploy_in, test_svc, selector)
        deploy['replicas'] = 1
        for rsc in [ns, deploy, svc]:
            template = env.get_template(rsc['template'])
            rend_temp = template.render(input=rsc)
            temp_name = gen_template_name(rsc['name'])
            lib_helper.dump_template(temp_name, rend_temp)
            lib.create_resource(temp_name, base_fixture)

        contract = config['system_id'] + "_svc_" + svc_ns + "_" + svc_name

        # 3 ) Case 1 : Custom service graph should be selected
        # Annotate the service with opflex.cisco.com/service-graph-name: <some value>
        annotate_svc_with_service_graph_name(svc_name, svc_ns, custom_graph_name)
        # Edit contract to use the custom service graph template
        apic.set_service_graph_template(custom_graph_name, contract)
        # Check custom service graph should be used
        lib.check_svc_graph_used(apic, custom_graph_name, contract, timeout=POLL_TIMEOUT)

        # 3) Case 2 : Custom service graph should not be used, if we remove anotation
        # Remove Annotation
        remove_annotate_svc_with_service_graph_name(svc_name, svc_ns)
        apic.set_service_graph_template(custom_graph_name, contract)
        # Check custom service graph should not be used
        lib.check_svc_graph_not_used(apic, custom_graph_name, contract, timeout=POLL_TIMEOUT)
    finally:
        # 4) Delete custom service graph template
        apic.del_custom_service_graph(custom_graph_name)
