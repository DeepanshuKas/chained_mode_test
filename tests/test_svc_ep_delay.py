import pytest
import json, time
from json import JSONEncoder
from tests import lib, lib_helper
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.template_utils import env
from tests.test_datapath import _get_input_for_svc_and_deployment, \
     _get_input_for_namespace
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
        APIC_USERNAME,
        APIC_PASSWORD)


LOG = logger.get_logger(__name__)
CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'
COMMON_DELAY = 120
SERVICE_DELAY = 60
SERVICE1_NAME = "service-name-1"
SERVICE2_NAME = "service-name-2"
SERVICE1_NAMESPACE = "service-ns-1"
SERVICE2_NAMESPACE = "service-ns-2"
TIMEOUT = 120
INTERVAL = 10


# subclass JSONEncoder
class DataEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

def remove_service_graph_endpoint_add_delay():
    """ Remove service-graph-endpoint-add-delay 
        from controller-config in Config Map. """
    kapi = KubeAPI()
    LOG.info("Removing service-graph-endpoint-add-delay from ConfigMap")
    try:
        config_map = lib.get_detail('ConfigMap', 
                                    name=CONFIGMAP_NAME,
                                    namespace=CONFIGMAP_NAMESPACE)
    
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", CONFIGMAP_NAME)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    config_map['data']['controller-config'] = \
        json.loads(config_map['data']['controller-config'])
    removed_value = config_map['data']['controller-config'].\
        pop('service-graph-endpoint-add-delay', None)
    if not removed_value:
        return

    LOG.info("Removing %s", removed_value)
    #Encoding the data to JSON Serializable
    config_map['data']['controller-config'] = json.dumps(config_map['data']\
        ['controller-config'], indent=4, cls=DataEncoder)

    patch_params = {'update_str' : json.dumps(
                        [{"op": "add",
                            "path": "/data/controller-config",
                            "value": config_map['data']['controller-config']}]),
                    'type' : 'json'}

    kapi.patch('ConfigMap', name=CONFIGMAP_NAME, patch_params=patch_params,
            namespace=CONFIGMAP_NAMESPACE)
    # Restart Controller 
    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)


def add_service_graph_endpoint_add_delay(pbr_svc_ep_delay):
    """ Add service-graph-endpoint-add-delay
        inside controller-config in Config Map. """

    kapi = KubeAPI()
    LOG.info("Adding service-graph-endpoint-add-delay in ConfigMap")
    try:
        config_map = lib.get_detail('ConfigMap', 
                                    name=CONFIGMAP_NAME,
                                    namespace=CONFIGMAP_NAMESPACE)
    
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s Config Map does not exist", CONFIGMAP_NAME)
        assert False, ("Validating config map failed, Reason: %s" % e.message)

    config_map['data']['controller-config'] = \
        json.loads(config_map['data']['controller-config'])

    # Add service-graph-endpoint-add-delay field
    config_map['data']['controller-config']\
        ["service-graph-endpoint-add-delay"] = pbr_svc_ep_delay

    #Encoding the data to JSON Serializable
    config_map['data']['controller-config'] = json.dumps(config_map['data']\
        ['controller-config'], indent=4, cls=DataEncoder)

    patch_params = {'update_str' : json.dumps(
                        [{"op": "add",
                            "path": "/data/controller-config",
                            "value": config_map['data']['controller-config']}]),
                    'type' : 'json'}

    kapi.patch('ConfigMap', name=CONFIGMAP_NAME, patch_params=patch_params,
            namespace=CONFIGMAP_NAMESPACE)

    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)


def check_for_service_graph_instance(service_name, namespace="default"):

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    system_id = apic_provision['aci_config']['system_id']
    l3out = apic_provision['aci_config']['l3out']['name']
    ext_network = apic_provision['aci_config']['l3out']['external_networks'][0]
    vrf_name = apic_provision['aci_config']['vrf']['name']
    config = {
        'apic_host': apic_host,
        'apic_username': APIC_USERNAME,
        'apic_password': APIC_PASSWORD,
        'system_id': system_id,
        'l3out': l3out,
        'ext_network': ext_network,
        'vrf_name': vrf_name,
        'snat_policy_for_service': True,
    }

    apic = ValidateApi(config)

    resource_suffix = "_svc_" + namespace + "_" + service_name
    graph_instance = contract = system_id + resource_suffix

    LOG.info("graph_instance %s" % graph_instance)
    max_time = time.time() + TIMEOUT
    while True:
        graph_instance_res = apic.is_service_graph_instance_exist(
            graph_instance, contract)
        if graph_instance_res or time.time() >= max_time:
            inst = {'GraphInstance': {graph_instance: graph_instance_res}}
            LOG.info(inst)
            break
        LOG.info("Retrying validation for graph instance [%s]" % graph_instance)
        time.sleep(INTERVAL)

    assert graph_instance_res, ("Graph Instance %s Not Exist" % graph_instance)


def get_input_for_svc_delay(c_delay, s_delay, is_sdelay = True):
    svc1 = {
        'name': SERVICE1_NAME,
        'namespace': SERVICE1_NAMESPACE,
    }
    svc2 = {
        'name': SERVICE2_NAME,
        'namespace': SERVICE2_NAMESPACE,
        'delay' : s_delay
    }

    pbr_in =  {"delay": c_delay, "services": [svc1, svc2]}

    if is_sdelay :
        return svc2, pbr_in
    else :
        return svc1, pbr_in


def start_svc_ep_delay_test(base_fixture, gen_template_name, c_delay,
    s_delay, is_sdelay=True):
    """Test service_endpoint_delay.

    This test performs below steps.
    1) Add service-graph-endpoint-add-delay in configmap
    2) Create a Namespace, LB service and Service endpoint
    3) Restart Service endpoint Pod
    4) Check No connectivity to LBS for specified delay
    5) Check connectivity to LBS
    6) Remove service-graph-endpoint-add-delay from configmap
    """
    test_svc, pbr_in = get_input_for_svc_delay(
        c_delay, s_delay, is_sdelay)
    svc_name = test_svc["name"]
    svc_ns = test_svc["namespace"]

    # 1) Add service-graph-endpoint-add-delay in configmap
    add_service_graph_endpoint_add_delay(pbr_in)

    # 2) Create a Namespace, LB service and Service endpoint
    selector = {'name': svc_name}
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
    
    wait_time = c_delay
    if is_sdelay:
        wait_time = s_delay

    try:
        # 3) Restart Service endpoint Pod
        lib.restart_pods(selector, svc_ns)
        lib.wait_for_svc_ep_ready(svc_name, svc_ns)
    
        # 4) Check No connectivity to LBS upto wait_time
        lib_helper.check_no_lbs_conn_from_ext_ip(svc_name, svc_ns,
            timeout=wait_time)

        # Check for service_graph_instance_exist and applied 
        check_for_service_graph_instance(svc_name, svc_ns)

        # 5) Check connectivity to LBS
        lib_helper.check_lbs_conn_from_ext_ip(svc_name, svc_ns) 

    finally:
        # 6) Remove service-graph-endpoint-add-delay from configmap
        remove_service_graph_endpoint_add_delay()

@pytest.mark.usefixtures("clean_gen_templates")
def test_svc_ep_common_delay(base_fixture, gen_template_name):
    # Test Common Delay
    start_svc_ep_delay_test(base_fixture, gen_template_name, COMMON_DELAY,
        SERVICE_DELAY, is_sdelay=False)

@pytest.mark.usefixtures("clean_gen_templates")
def test_svc_ep_svc_delay(base_fixture, gen_template_name):
    # Test Per Service Delay
    start_svc_ep_delay_test(base_fixture, gen_template_name, COMMON_DELAY,
        SERVICE_DELAY, is_sdelay=True)

