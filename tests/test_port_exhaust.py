import pytest

import time

from acc_pyutils.api import KubeAPI
from tests import lib, validate_snat_apic_resource
from tests.input.cfg import (APIC_VALIDATION, CRD_NAMESPACE)
from tests.test_snat import DATA_DIR

# Notes - Below test requires that the two pods to be launched on
#         two different cluster nodes. Test expects 'busybox' yamls
#         mentioned in below tests, should have 'nodeSelector' value
#         filled based on the target cluster nodes.


@pytest.mark.skip(reason="test is not functional in this release")
def test_port_exhaust(base_fixture):
    lib.update_snat_op_cfg_configmap('59999')
    # VK: restarting of controller not needed any more after configmap update
    # lib.restart_controller()

    # Notes - Check 'nodeSelector' value
    pod1 = lib.create_resource('{}/busybox_port_exhaust_1_1.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod1['name'])

    policy = lib.create_resource('{}/port_exhaust_policy_1.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_verified_snatpolicy(name=policy['name'])

    pod2 = lib.create_resource('{}/busybox_port_exhaust_1_2.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod2['name'])

    snat_policy = lib.get_verified_snatpolicy(name=policy['name'])
    assert snat_policy['status']['state'] == "IpPortsExhausted"

    lib.update_snat_op_cfg_configmap('3000')


@pytest.mark.skip(reason="test is not functional in this release")
def test_port_exhaust_after_pod_launch(base_fixture):
    # Notes - Check 'nodeSelector' value
    pod1 = lib.create_resource('{}/busybox_port_exhaust_2_1.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod1['name'])

    pod2 = lib.create_resource('{}/busybox_port_exhaust_2_2.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod2['name'])

    policy = lib.create_resource('{}/port_exhaust_policy_2.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_verified_snatpolicy(name=policy['name'])

    try:
        lib.update_snat_op_cfg_configmap('59999')
        snat_policy = lib.get_verified_snatpolicy(name=policy['name'])
        assert snat_policy['status']['state'] == "IpPortsExhausted"
    except Exception:
        raise
    finally:
        lib.update_snat_op_cfg_configmap('3000')


@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_with_non_default_port_distribution_b(base_fixture):
    lib.create_resource(
        '{}/port_distribution_ns.yaml'.format(DATA_DIR), base_fixture)
    pod = lib.create_resource('{}/port_distribution_pod.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'],
                                           namespace=pod['namespace'])

    policy = lib.create_resource(
        '{}/port_distribution_snat_policy.yaml'.format(DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    lib.validate_pod_ep_file(
        uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(
        hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    dest_ips = lib.get_dest_ips_from_config(count=1)
    lib.validate_traffic_for_given_destination(pod['manifest_dir'],
                                               pod['name'],
                                               snat_ips[0],
                                               dest_ips=dest_ips,
                                               namespace=pod['namespace'])
    try:
        lib.update_snat_op_cfg_configmap('5000')
        lib.validate_traffic_for_given_destination(pod['manifest_dir'],
                                                   pod['name'],
                                                   snat_ips[0],
                                                   dest_ips=dest_ips,
                                                   namespace=pod['namespace'])
    except Exception:
        raise
    finally:
        lib.update_snat_op_cfg_configmap('3000')


@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_port_over_limit_b(base_fixture):
    kapi = KubeAPI()
    lib.create_resource(
        '{}/port_over_limit_ns.yaml'.format(DATA_DIR), base_fixture)
    deployment = lib.create_resource(
        '{}/port_over_limit_nginx_deploy.yaml'.format(DATA_DIR),
        base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deployment['name'], namespace=deployment['namespace'])

    policy = lib.create_resource(
        '{}/port_over_limit_snat_policy.yaml'.format(DATA_DIR), base_fixture)
    snat_policy = lib.get_detail('SnatPolicy',
                                 name=policy['name'],
                                 namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=deployment['namespace'], **kwargs)

    dest_ips = lib.get_dest_ips_from_config(count=1)

    _verify_pod_snat_traffic(deployment, dest_ips, pods, policy, snat_ids,
                             snat_ips)
    try:
        lib.update_snat_op_cfg_configmap('59999')
        kapi.exec_cli_cmd("kubectl scale --replicas=2 deployment %s -n %s" %
                          (deployment['name'], deployment['namespace']))
        snat_policy = lib.get_verified_snatpolicy(name=policy['name'])
        assert snat_policy['status']['state'] == "IpPortsExhausted"
        kwargs = {'labels': ','.join(labels)}
        pods = kapi.get_detail('pod', **kwargs)
        _verify_pod_snat_traffic(deployment, dest_ips, pods, policy, snat_ids,
                                 snat_ips)
    except Exception:
        raise
    finally:
        lib.update_snat_op_cfg_configmap('3000')


@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_globalinfo_on_configmap_update(base_fixture):
    """ SNAT configmap update test where the config-map gets updated with
        the same values. If SNAT configmap gets updated but the start and
        end ports, or the portrange does not change, then the snatglobalinfo
        should not change after that configmap change is done.
    """
    # Get the configmap info
    kapi = KubeAPI()
    snat_cm = kapi.get_detail('configmap', name='snat-operator-config',
                              namespace=CRD_NAMESPACE)
    ports_per_node = snat_cm['data']['ports-per-node']
    start = snat_cm['data']['start']
    end = snat_cm['data']['end']

    # Creating pod
    pod = lib.create_resource('{}/busybox.yaml'.format(DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    # Creating policy
    policy = lib.create_resource('{}/sample_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    # Get the snatglobalinfo resourceVersion
    globalinfo = kapi.get_detail('SnatGlobalInfo', 'snatglobalinfo',
                            namespace=CRD_NAMESPACE)
    resource_version_old = globalinfo['metadata']['resourceVersion']

    # Update the configmap with same value
    lib.update_snat_op_cfg_configmap(ports_per_node, start, end)
    time.sleep(10)

    # Get the snatglobalinfo resourceVersion after configmap update
    globalinfo = kapi.get_detail('SnatGlobalInfo', 'snatglobalinfo',
                            namespace=CRD_NAMESPACE)
    resource_version = globalinfo['metadata']['resourceVersion']

    if (resource_version != resource_version_old):
        raise Exception(
            "Err: snatglobalinfo got updated with same SNAT configmap values")


def _verify_pod_snat_traffic(deployment, dest_ips, pods, policy, snat_ids,
                             snat_ips):
    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        lib.validate_pod_ep_file(pod_uid,
                                 hostname,
                                 deployment['manifest_dir'],
                                 snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(hostname,
                                                    snat_ip_info,
                                                    policy['manifest_dir'],
                                                    snat_ips)

        lib.validate_traffic_for_given_destination(deployment['manifest_dir'],
                                                   pod['metadata']['name'],
                                                   snat_ips[0],
                                                   dest_ips=dest_ips,
                                                   namespace=deployment[
                                                       'namespace'])
