import os
import time

from tests.apic_apis import ApicApi
from acc_pyutils import logger
from collections import OrderedDict
from tests.apic_validate import ValidateApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
from tests import lib, lib_helper

CONFIG_FILE = os.path.abspath('tests/input/cfg.py')

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')

# Returns a dictionary of podif data for ERSPAN matched labels.
def get_podif_data(policy):
    erspan_policy = lib.get_detail(
        'ErspanPolicy', name=policy['name'], namespace=policy['namespace'])
    podifs = []
    podif_data = {}
    namespace = erspan_policy['spec']['selector']['namespace']
    if 'labels' in erspan_policy['spec']['selector']:
        labels = erspan_policy['spec']['selector']['labels']
        if labels is not None:
            pods = lib_helper.get_pod_details_by_labels(labels)
    elif 'labels' not in erspan_policy['spec']['selector'] and namespace is not None:
        pods = lib_helper.get_pod_details_by_namespace(namespace)
    
    for pod in pods:
        podif = lib.get_podif_name(name=pod[0], namespace=pod[1])
        podifs.append(podif)
    
    for podif in podifs:
        if podif not in podif_data:
            podif_data[podif] = []
        ap = lib.get_podif_app_profile(name=podif, namespace='kube-system')
        podif_data[podif].append(ap)
        epg = lib.get_podif_epg(name=podif, namespace='kube-system')
        podif_data[podif].append(epg)
        mac = lib.get_podif_mac(name=podif, namespace='kube-system')
        podif_data[podif].append(mac)
    return podif_data
    
def erspan_client_end_points(policy):
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    domain_name = apic_provision['aci_config']['system_id']
    
    podif_data = get_podif_data(policy)
    ceps = {}
    for podif_d in podif_data:
        if podif_d not in ceps:
            ceps[podif_d] = []
        src_ref_dn = "uni/tn-" + domain_name + "/ap-" + podif_data[podif_d][0] + "/epg-" + podif_data[podif_d][1] + "/cep-" + podif_data[podif_d][2]
        ceps[podif_d].append(podif_data[podif_d][2])
        ceps[podif_d].append(src_ref_dn)
    return ceps    

# Checks for mirror in the ovs pods which live on the same nodes as the erspan source pods.
def check_mirror_in_ovs(domain_name, policy, erspanpolicy_name):
    erspan_policy = lib.get_detail(
        'ErspanPolicy', name=policy['name'], namespace=policy['namespace'])
    nodes = []
    ovs_nodes = []
    label = {'name': 'aci-containers-openvswitch'}
    namespace = erspan_policy['spec']['selector']['namespace']
    ovs_pods = lib_helper.get_pods_by_labels(label, namespace='aci-containers-system')
    if 'labels' in erspan_policy['spec']['selector']:
        labels = erspan_policy['spec']['selector']['labels']
        if labels is not None:
            matching_pods = lib_helper.get_pod_details_by_labels(labels)
    elif 'labels' not in erspan_policy['spec']['selector'] and namespace is not None:
        matching_pods = lib_helper.get_pod_details_by_namespace(namespace)
    for pod in matching_pods:
        _,  _, hostname = lib.get_pod_details(name=pod[0])
        nodes.append(hostname)
    for pod in ovs_pods:
        _,  _, hostname = lib.get_pod_details(name=pod[0], namespace='aci-containers-system')
        ovs_nodes.append(hostname)
    node_set = [node for node in ovs_nodes if node in nodes]

    ovs_pods_dict = {}
    for pod in ovs_pods:
        _,  _, hostname = lib.get_pod_details(name=pod[0], namespace='aci-containers-system')
        if hostname in node_set and hostname not in ovs_pods_dict:
            ovs_pods_dict[hostname] = []
            ovs_pods_dict[hostname].append(pod)
        elif hostname in node_set and hostname in ovs_pods_dict:
            ovs_pods_dict[hostname].append(pod)
    pod_namespace = "aci-containers-system"
    mirror_name = domain_name + "_span_" + erspanpolicy_name
    for node_key in ovs_pods_dict:
        pod_name = ovs_pods_dict[node_key][0][0]
        cmd = 'kubectl exec -it --namespace=%s %s -- ovs-vsctl get Mirror %s name' % (pod_namespace,pod_name,mirror_name)
        lib.exec_cmd(cmd)

def test_apic(erspan_policy_name, ceps, policy):

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

    infra_path = "/api/mo/uni/infra"
    spanSrcGrp_dn = "/vsrcgrp-" + domain_name + "_span_" + erspan_policy_name
    spanSrcGrp_url = infra_path + spanSrcGrp_dn + ".json"
    srcGrp_resp = aci.get(spanSrcGrp_url)
    assert int(srcGrp_resp['totalCount']) != 0, "Failed to push spanVSrcGrp Mo to APIC"

    if len(ceps) != 0:
        for cep in ceps:
            spanSrc_dn = spanSrcGrp_dn + "/vsrc-" + domain_name + "_span_" + erspan_policy_name + "_Src_" + lib.transform_mac(ceps[cep][0])
            spanSrc_url = infra_path + spanSrc_dn + ".json"
            src_resp = aci.get(spanSrc_url)
            assert int(src_resp['totalCount']) != 0, "Failed to push spanVSrc Mo to APIC"

            spanRsSrcToVPort_dn = spanSrc_dn + "/rssrcToVPort-[" + ceps[cep][1] + "]"
            spanRsSrcToVPort_url = infra_path + spanRsSrcToVPort_dn + ".json"
            spanRsSrcToVPort_resp = aci.get(spanRsSrcToVPort_url)
            assert int(spanRsSrcToVPort_resp['totalCount']) != 0, "Failed to push spanRsSrcToVPort Mo to APIC"

    spanDstGrp_dn = "/vdestgrp-" + domain_name + "_span_" + erspan_policy_name
    spanDstGrp_url = infra_path + spanDstGrp_dn + ".json"
    srcDst_resp = aci.get(spanDstGrp_url)
    assert int(srcDst_resp['totalCount']) != 0, "Failed to push spanVDestGrp Mo to APIC"

    spanDst_dn = spanDstGrp_dn + "/vdest-" + domain_name + "_span_" + erspan_policy_name + "_Dest"
    spanDst_url = infra_path + spanDst_dn + ".json"
    dst_resp = aci.get(spanDst_url)
    assert int(dst_resp['totalCount']) != 0, "Failed to push spanVDest Mo to APIC"

    spanDstSum_dn = spanDst_dn + "/vepgsummary"
    spanDstSum_url = infra_path + spanDstSum_dn + ".json"
    dstSum_resp = aci.get(spanDstSum_url)
    assert int(dstSum_resp['totalCount']) != 0, "Failed to push spanVEpgSummary Mo to APIC"
    
    vpcs = aci_client.get_vpcs_from_fabric_paths()
    if len(vpcs)!= 0:
        for vpc in vpcs:
            rsDest_dn = "/funcprof/accbundle-" + vpc + "/rsspanVDestGrp-" + domain_name + "_span_" + erspan_policy_name
            rsDest_url = infra_path + rsDest_dn + ".json"
            rsDest_resp = aci.get(rsDest_url)
            assert int(rsDest_resp['totalCount']) != 0, "Failed to push infraRsSpanVDestGrp Mo to APIC"
            
            rsSrc_dn = "/funcprof/accbundle-" + vpc + "/rsspanVSrcGrp-" + domain_name + "_span_" + erspan_policy_name
            rsSrc_url = infra_path + rsSrc_dn + ".json"
            rsSrc_resp = aci.get(rsSrc_url)
            assert int(rsSrc_resp['totalCount']) != 0, "Failed to push infraRsSpanVSrcGrp Mo to APIC"
            assert int(rsSrc_resp['totalCount']) != 0, "Failed to push infraRsSpanVSrcGrp Mo to APIC"

    pcs = aci_client.get_pcs_from_fabric_paths()
    if len(pcs)!= 0:
        for pc in pcs:
            rsDest_dn = "/funcprof/accbundle-" + pc + "/rsspanVDestGrp-" + domain_name + "_span_" + erspan_policy_name
            rsDest_url = infra_path + rsDest_dn + ".json"
            rsDest_resp = aci.get(rsDest_url)
            assert int(rsDest_resp['totalCount']) != 0, "Failed to push infraRsSpanVDestGrp Mo to APIC"
            
            rsSrc_dn = "/funcprof/accbundle-" + pc + "/rsspanVSrcGrp-" + domain_name + "_span_" + erspan_policy_name
            rsSrc_url = infra_path + rsSrc_dn + ".json"
            rsSrc_resp = aci.get(rsSrc_url)
            assert int(rsSrc_resp['totalCount']) != 0, "Failed to push infraRsSpanVSrcGrp Mo to APIC"
            assert int(rsSrc_resp['totalCount']) != 0, "Failed to push infraRsSpanVSrcGrp Mo to APIC"

