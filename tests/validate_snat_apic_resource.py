import os
import time

from acc_pyutils import logger
from collections import OrderedDict
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
from tests import lib_helper

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')
# waiting time for service graph instance to change its state
# from appying to applied
TIMEOUT = 120
INTERVAL = 15


def check_and_transform_ips_with_submask(snat_ip_list):
    ips = list()
    for ip in snat_ip_list:
        if "/" in ip:
            ips.append(ip.split("/")[0])
        else:
            ips.append(ip)
    return ips


def test_apic(snat_ip, snat_policy_for_service=False,
              namespace="default", service_name=None, filtered_nodes=[]):

    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    snat_ip = check_and_transform_ips_with_submask(snat_ip)
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
        'snat_ip': snat_ip
    }

    # validate all input config
    for key, value in config.items():
            assert value, '%s not configured in %s file.' % (
                key, CONFIG_FILE)
    config.update({'snat_policy_for_service': snat_policy_for_service})
    try:
        apic = ValidateApi(config)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, CONFIG_FILE))
    result_data = OrderedDict()
    output = True
    system_id = config['system_id']
    l3out = config['l3out']

    if snat_policy_for_service:
        if not service_name:
            assert False, "service name is not provided."
        resource_suffix = "_svc_" + namespace + "_" + service_name
    else:
        resource_suffix = "_snat_svcgraph"

    if not snat_policy_for_service:
        filter_1 = system_id + resource_suffix + "_fromCons-toProv"
        filter_2 = system_id + resource_suffix + "_fromProv-toCons"
    else:
        filter_name = system_id + resource_suffix

    contract = system_id + resource_suffix
    graph_name = system_id + "_" + "svc" + "_" + "global"
    if snat_policy_for_service:
        context = vrf_name
    else:
        context = "uni"

    graph_instance = system_id + resource_suffix + '-' + \
        system_id + '_svc_global-' + context
    redirect_policy = system_id + resource_suffix + '-' + system_id + \
        '_svc_global-loadbalancer'

    # check existance of service graph contract
    contract_result = apic.is_snat_svcgraph_contract_exist(contract)
    cont = {'Contract': {contract: contract_result}}
    result_data.update(cont)

    l3out_result = apic.validate_l3out(l3out, contract)
    l3out_out = {'L3out': {l3out: l3out_result}}
    result_data.update(l3out_out)

    abs_graph_result = apic.is_abstract_graph_exist(graph_name)
    abs_out = {'AbstractGraph': {graph_name: abs_graph_result}}
    result_data.update(abs_out)

    policy = apic.validate_device_selections_policy(
        redirect_policy, contract, snat_policy_for_service, filtered_nodes)
    pol_out = {'RedirectPolicy': {redirect_policy: policy}}
    result_data.update(pol_out)
    max_time = time.time() + TIMEOUT
    while True:
        graph_instance_res = apic.is_service_graph_instance_exist(
            graph_instance, contract)
        if graph_instance_res or time.time() >= max_time:
            inst = {'GraphInstance': {graph_instance: graph_instance_res}}
            result_data.update(inst)
            break
        LOG.info("---Retrying validation for graph "
                 "instance [%s]" % graph_instance)
        time.sleep(INTERVAL)

    filt = {'Filter': {}}
    if not snat_policy_for_service:
        for _filter_name in [filter_1, filter_2]:
            _filter_result = apic.validate_filter_and_entry(_filter_name)
            filt['Filter'][_filter_name] = _filter_result
    else:
        filter_result = apic.validate_filter_and_entry(filter_name)
        filt['Filter'][filter_name] = filter_result

    LOG.info("Filter result : %s" % filt)
    result_data.update(filt)

    LOG.info("--------- Output of apic snat resource validation---------")
    for key, value in result_data.items():
        for resource_name, resource_availability in value.items():
            status = "failed" if not resource_availability else "success"
            LOG.info("Validation is %s for %s [%s]" % (status,
                     key, resource_name))
            if not resource_availability:
                output = False
    if not output:
        assert False, ("APIC snat resource validations failed.")
