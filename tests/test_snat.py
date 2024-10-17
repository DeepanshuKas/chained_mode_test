import json
import os

from threading import Thread
import pytest
import random

from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from acc_pyutils.utils import copy_updated_yaml
from tests import lib, validate_snat_apic_resource, test_tuneup
from tests import lib_helper
from tests.input.cfg import (APIC_VALIDATION, CRD_NAMESPACE)
from tests.lib_helper import get_template
from tests.test_chained_mode import check_chained_mode

DATA_DIR = os.path.abspath('tests/test_data')
LOG = logger.get_logger(__name__)

pytestmark = pytest.mark.skipif(check_chained_mode() is True, reason="Setup : "
                                "Not applicable for chained mode")
@pytest.mark.smoke
def test_snat_for_pod(base_fixture):
    pod = lib.create_resource('{}/busybox.yaml'.format(DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    policy = lib.create_resource('{}/sample_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    # REVISIT (VK) -
    # snat_allocation = snat_policy['status']['snat-allocation']
    # snat_node_ip_assoc = validate_snat_ip_allocation(snat_allocation)

    # lib.validate_pod_ep_file(uid, hostname, pod['manifest_dir'], snat_ips)
    lib.validate_pod_ep_file(uid, hostname, pod['manifest_dir'],
                             snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(
        hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0])


def test_snat_for_deployment(base_fixture):
    kapi = KubeAPI()

    deployment = lib.create_resource(
        '{}/nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deployment['name'])

    policy = lib.create_resource(
        '{}/sample_snat_policy.yaml'.format(DATA_DIR), base_fixture)
    snat_policy = lib.get_detail('SnatPolicy',
                                 name=policy['name'],
                                 namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

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

        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0])


def test_multiple_external_ip_reachability(base_fixture):
    pod = lib.create_resource('{}/busybox_multi_target.yaml'.format(DATA_DIR),
                              base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    policy = lib.create_resource('{}/multi_target_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    snat_policy = lib.get_detail('SnatPolicy',
                                 name=policy['name'],
                                 namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    lib.validate_pod_ep_file(uid, hostname, pod['manifest_dir'],
                             snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(
        hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                         verify_multiple_targets=True)


@pytest.mark.smoke
def test_snat_policy_for_service(base_fixture):
    kapi = KubeAPI()

    deployment = lib.create_resource(
        '{}/nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'])

    svc1 = lib.create_resource('{}/nginx_service.yaml'.format(DATA_DIR),
                               base_fixture)
    # Issue(VK) - According to Jayaram, the order may be issue with sept6
    # image. So first deleting service followed by deployment.
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
    )
    policy = lib.create_resource('{}/sample_svc_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids = lib.get_snat_ids_for_service(svc1)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True,
                                              svc_namespace, svc1['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0])


@pytest.mark.skipif(lib.is_valid_cluster_for_snat_ds_test() is False,
                    reason="Not applicable on this setup!!")
def test_snat_policy_for_service_with_ds(base_fixture):
    kapi = KubeAPI()

    ds = lib.create_resource(
        '{}/nginx_ds.yaml'.format(DATA_DIR), base_fixture)
    labels = lib.get_ds_details(name=ds['name'])

    svc1 = lib.create_resource('{}/nginx_service.yaml'.format(DATA_DIR),
                               base_fixture)
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
    )
    policy = lib.create_resource('{}/sample_svc_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids = lib.get_snat_ids_for_service(svc1)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True,
                                              svc_namespace, svc1['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, ds['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            ds['manifest_dir'], pod['metadata']['name'], snat_ips[0])


def test_snat_policy_on_namespace_for_service(base_fixture):
    kapi = KubeAPI()

    namespace = lib.create_resource(
        '{}/case_3_namespace.yaml'.format(DATA_DIR), base_fixture)

    deployment = lib.create_resource(
        '{}/case_3_nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deployment['name'], namespace=namespace['name'])

    svc1 = lib.create_resource('{}/case_3_nginx_service.yaml'.format(
        DATA_DIR), base_fixture)

    policy = lib.create_resource('{}/case_3_svc_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids = lib.get_snat_ids_for_service(svc1)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True,
                                              svc_namespace, svc1['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=namespace['name'], **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0],
            namespace=pod['metadata']['namespace'])


def test_snat_policy_on_cluster(base_fixture):
    lib.create_resource('{}/case_5_namespace.yaml'.format(DATA_DIR),
                        base_fixture)

    bb1 = lib.create_resource('{}/case_5_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    bb2 = lib.create_resource('{}/case_5_busybox_2.yaml'.format(DATA_DIR),
                              base_fixture)

    policy = lib.create_resource('{}/case_5_cluster_policy.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()
    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    for pod in [bb1, bb2]:
        uid, _, hostname = lib.get_pod_details(
            name=pod['name'], namespace=pod['namespace'])

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                             namespace=pod['namespace'])


def test_snat_policy_on_cluster_by_labels(base_fixture):
    lib.create_resource('{}/case_6_namespace.yaml'.format(DATA_DIR),
                        base_fixture)

    bb1 = lib.create_resource('{}/case_6_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    bb2 = lib.create_resource('{}/case_6_busybox_2.yaml'.format(DATA_DIR),
                              base_fixture)

    policy = lib.create_resource('{}/case_6_policy.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    for pod in [bb1, bb2]:
        uid, _, hostname = lib.get_pod_details(
            name=pod['name'], namespace=pod['namespace'])

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                             namespace=pod['namespace'])


def test_snat_policy_on_namespace_without_using_labels(base_fixture):
    lib.create_resource('{}/case_7_namespace.yaml'.format(DATA_DIR),
                        base_fixture)

    bb = lib.create_resource('{}/case_7_busybox.yaml'.format(DATA_DIR),
                             base_fixture)
    ngnx = lib.create_resource('{}/case_7_nginx.yaml'.format(DATA_DIR),
                               base_fixture)

    policy = lib.create_resource('{}/case_7_policy.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    for pod in [bb, ngnx]:
        uid, _, hostname = lib.get_pod_details(
            name=pod['name'], namespace=pod['namespace'])

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                             namespace=pod['namespace'])


def test_basic_snat_ip_update_test(base_fixture):
    kapi = KubeAPI()

    pod = lib.create_resource('{}/busybox.yaml'.format(DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'])

    policy = lib.create_resource('{}/sample_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    lib.validate_pod_ep_file(
        uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(
        hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0])

    updated_manifest = lib.update_snat_policy_ip(
        '{}/sample_snat_policy.yaml'.format(DATA_DIR),
        policy['manifest_dir'],
        ['10.3.99.99/32'])

    status = kapi.apply(updated_manifest,
                        label=policy['add_label'],
                        manifest_dir=policy['manifest_dir'],
                        delay=test_tuneup.get('apply_delay', 10))
    assert status is True, 'Failed to update SNAT policy - %s' % policy[
        'name']

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(['10.3.99.99'])

    lib.validate_traffic(pod['manifest_dir'], pod['name'], '10.3.99.99')


def test_snat_ip_update_for_deployment(base_fixture):
    kapi = KubeAPI()

    deployment = lib.create_resource(
        '{}/nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deployment['name'])

    policy = lib.create_resource(
        '{}/sample_snat_policy.yaml'.format(DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

    def _validate_deployment(snat_ids, snat_ips):
        for pod in pods['items']:
            pod_uid = pod['metadata']['uid']
            hostname = pod['spec']['nodeName']

            lib.validate_pod_ep_file(pod_uid,
                                     hostname,
                                     deployment['manifest_dir'],
                                     snat_ids=snat_ids)
            snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
            lib.validate_snat_file_on_host_for_snat_ips(
                hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

            lib.validate_traffic(deployment['manifest_dir'],
                                 pod['metadata']['name'],
                                 snat_ips[0])

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    _validate_deployment(snat_ids, snat_ips)

    updated_manifest = lib.update_snat_policy_ip(
        '{}/sample_snat_policy.yaml'.format(DATA_DIR),
        policy['manifest_dir'],
        ['10.3.133.133/32'])
    status = kapi.apply(updated_manifest,
                        label=policy['add_label'],
                        manifest_dir=policy['manifest_dir'],
                        delay=test_tuneup.get('apply_delay', 10))
    assert status is True, 'Failed to update SNAT policy - %s' % policy[
        'name']

    updated_snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    updated_snat_ips = lib.get_allocated_snat_ips_from_policy(
        updated_snat_policy)
    updated_snat_ids = lib.get_snat_ids_from_policy(updated_snat_policy)

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(updated_snat_ips)

    _validate_deployment(updated_snat_ids, updated_snat_ips)


def test_snat_ip_update_on_namespace_without_using_labels(base_fixture):
    kapi = KubeAPI()

    ns = lib.create_resource('{}/case_12_namespace.yaml'.format(DATA_DIR),
                             base_fixture)

    bb = lib.create_resource('{}/case_12_busybox.yaml'.format(DATA_DIR),
                             base_fixture)
    ngnx = lib.create_resource('{}/case_12_nginx.yaml'.format(DATA_DIR),
                               base_fixture)

    policy = lib.create_resource('{}/case_12_policy.yaml'.format(
        DATA_DIR), base_fixture)
    base_fixture['delete_info'].reverse()
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=ns['name'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    def _validate_pods_traffic(snat_ids, snat_ips):
        for pod in [bb, ngnx]:
            uid, _, hostname = lib.get_pod_details(
                name=pod['name'], namespace=pod['namespace'])

            lib.validate_pod_ep_file(
                uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
            snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
            lib.validate_snat_file_on_host_for_snat_ips(
                hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

            lib.validate_traffic(
                pod['manifest_dir'], pod['name'], snat_ips[0],
                namespace=pod['namespace'])

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    _validate_pods_traffic(snat_ids, snat_ips)
    updated_manifest = lib.update_snat_policy_ip(
        '{}/case_12_policy.yaml'.format(DATA_DIR),
        policy['manifest_dir'],
        ['10.3.225.225/32'])
    status = kapi.apply(updated_manifest,
                        label=policy['add_label'],
                        manifest_dir=policy['manifest_dir'],
                        delay=test_tuneup.get('apply_delay', 10))
    assert status is True, 'Failed to update SNAT policy - %s' % policy[
        'name']

    updated_snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    updated_snat_ips = lib.get_allocated_snat_ips_from_policy(
        updated_snat_policy)
    updated_snat_ids = lib.get_snat_ids_from_policy(
        updated_snat_policy)

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(updated_snat_ips)

    _validate_pods_traffic(updated_snat_ids, updated_snat_ips)


def test_snat_policy_label_update(base_fixture):
    kapi = KubeAPI()

    bb1 = lib.create_resource('{}/case_13_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    bb2 = lib.create_resource('{}/case_13_busybox_2.yaml'.format(DATA_DIR),
                              base_fixture)

    policy = lib.create_resource('{}/case_13_policy.yaml'.format(
        DATA_DIR), base_fixture)
    snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    def _validate_pod_traffic(pod, snat_ips):
        uid, _, hostname = lib.get_pod_details(
            name=pod['name'], namespace=pod['namespace'])

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            pod['manifest_dir'], pod['name'], snat_ips[0],
            namespace=pod['namespace'])

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    _validate_pod_traffic(bb1, snat_ips)
    # REVISIT(VK) -
    updated_manifest = lib.update_snat_policy_label(
        '{}/case_13_policy.yaml'.format(DATA_DIR),
        {'test1': 'case13-policy-l2'},
        manifest_dir=policy['manifest_dir'])
    status = kapi.apply(updated_manifest,
                        label=policy['add_label'],
                        manifest_dir=policy['manifest_dir'],
                        delay=test_tuneup.get('apply_delay', 10))
    assert status is True, 'Failed to update SNAT policy - %s' % policy[
        'name']

    updated_snat_policy = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])
    updated_snat_ips = lib.get_allocated_snat_ips_from_policy(
        updated_snat_policy)

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(updated_snat_ips)

    _validate_pod_traffic(bb2, updated_snat_ips)


def test_simple_multi_policy(base_fixture):
    lib.create_resource('{}/case_8_namespace.yaml'.format(DATA_DIR),
                        base_fixture)
    policy1 = lib.create_resource('{}/case_8_policy_1.yaml'.format(
        DATA_DIR), base_fixture)
    policy2 = lib.create_resource('{}/case_8_policy_2.yaml'.format(
        DATA_DIR), base_fixture)
    bb1 = lib.create_resource('{}/case_8_busybox_1.yaml'.format(DATA_DIR),
                              base_fixture)
    bb2 = lib.create_resource('{}/case_8_busybox_2.yaml'.format(DATA_DIR),
                              base_fixture)
    base_fixture['delete_info'].reverse()

    lib.verify_null_mac_file_on_nodes()

    for pod, policy in [(bb1, policy1), (bb2, policy2)]:
        uid, _, hostname = lib.get_pod_details(
            name=pod['name'], namespace=pod['namespace'])

        snat_policy = lib.get_detail('SnatPolicy',
                                     name=policy['name'],
                                     namespace=policy['namespace'])

        snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
        snat_ids = lib.get_snat_ids_from_policy(snat_policy)

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        if APIC_VALIDATION:
            validate_snat_apic_resource.test_apic(snat_ips)

        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                             namespace=pod['namespace'])


@pytest.mark.xfail
def test_namespace_label_fallback_policy(base_fixture):
    kapi = KubeAPI()

    lib.create_resource('{}/case_25_namespace.yaml'.format(DATA_DIR),
                        base_fixture)
    policy1 = lib.create_resource('{}/case_25_label_policy.yaml'.format(
        DATA_DIR), base_fixture)
    policy2 = lib.create_resource('{}/case_25_ns_policy.yaml'.format(
        DATA_DIR), base_fixture)
    bb = lib.create_resource('{}/case_25_busybox.yaml'.format(DATA_DIR),
                             base_fixture)
    ngnx = lib.create_resource('{}/case_25_nginx.yaml'.format(DATA_DIR),
                               base_fixture)
    base_fixture['delete_info'].reverse()

    lib.verify_null_mac_file_on_nodes()

    def _validate_policy_datapath(policy):
        for pod in [bb, ngnx]:
            uid, _, hostname = lib.get_pod_details(
                name=pod['name'], namespace=pod['namespace'])

            snat_policy = lib.get_detail('SnatPolicy',
                                         name=policy['name'],
                                         namespace=policy['namespace'])

            snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
            snat_ids = lib.get_snat_ids_from_policy(snat_policy)

            lib.validate_pod_ep_file(
                uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
            snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
            lib.validate_snat_file_on_host_for_snat_ips(
                hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

            if APIC_VALIDATION:
                validate_snat_apic_resource.test_apic(snat_ips)

            lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0],
                                 namespace=pod['namespace'])

    _validate_policy_datapath(policy1)
    kapi.delete_by_label(policy1['add_label'], policy1['manifest_dir'],
                         delay=test_tuneup.get('del_by_label_delay', 10))
    _validate_policy_datapath(policy2)


def test_cluster_namespace_label_fallback_policy(base_fixture):
    kapi = KubeAPI()

    lib.create_resource('{}/case_26_namespace.yaml'.format(DATA_DIR),
                        base_fixture)
    policy1 = lib.create_resource('{}/case_26_label_policy.yaml'.format(
        DATA_DIR), base_fixture)
    policy2 = lib.create_resource('{}/case_26_ns_policy.yaml'.format(
        DATA_DIR), base_fixture)
    policy3 = lib.create_resource('{}/case_26_cluster_policy.yaml'.format(
        DATA_DIR), base_fixture)
    bb = lib.create_resource('{}/case_26_busybox.yaml'.format(DATA_DIR),
                             base_fixture)
    ngnx = lib.create_resource('{}/case_26_nginx.yaml'.format(DATA_DIR),
                               base_fixture)
    base_fixture['delete_info'].reverse()

    lib.verify_null_mac_file_on_nodes()

    def _validate_policy_datapath(policy):
        for pod in [bb, ngnx]:
            uid, _, hostname = lib.get_pod_details(
                name=pod['name'], namespace=pod['namespace'])

            snat_policy = lib.get_detail('SnatPolicy',
                                         name=policy['name'],
                                         namespace=policy['namespace'])

            snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
            snat_ids = lib.get_snat_ids_from_policy(snat_policy)

            lib.validate_pod_ep_file(
                uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
            snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
            lib.validate_snat_file_on_host_for_snat_ips(
                hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

            if APIC_VALIDATION:
                validate_snat_apic_resource.test_apic(snat_ips)

            lib.validate_traffic(pod['manifest_dir'],
                                 pod['name'],
                                 snat_ips[0],
                                 namespace=pod['namespace'])

    _validate_policy_datapath(policy1)
    kapi.delete_by_label(policy1['add_label'], policy1['manifest_dir'],
                         delay=test_tuneup.get('del_by_label_delay', 10))
    _validate_policy_datapath(policy2)
    kapi.delete_by_label(policy2['add_label'], policy2['manifest_dir'],
                         delay=test_tuneup.get('del_by_label_delay', 10))
    _validate_policy_datapath(policy3)


def test_policy_cleanup_after_service_delete(base_fixture):
    kapi = KubeAPI()

    deployment = lib.create_resource(
        '{}/nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'])

    svc = lib.create_resource('{}/nginx_service.yaml'.format(DATA_DIR),
                              base_fixture)
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
    )
    policy = lib.create_resource('{}/sample_svc_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc)
    snat_ids = lib.get_snat_ids_for_service(svc)

    if APIC_VALIDATION:
        svc_namespace = svc['namespace'] if "namespace" in svc else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True,
                                              svc_namespace, svc['name'])

    lib.verify_null_mac_file_on_nodes()

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(pod_uid,
                                 hostname,
                                 deployment['manifest_dir'],
                                 snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0])

    kapi.delete_by_label(policy['add_label'], policy['manifest_dir'],
                         delay=test_tuneup.get('del_by_label_delay', 10))
    _, _, _, ingress = lib.get_service_details(svc['name'])
    lib.verify_globalinfo_cleared_after_delete(ingress[0]['ip'])


def test_multiple_snat_ip_scenarios(base_fixture):
    kapi = KubeAPI()

    ns = lib.create_resource(
        '{}/case_28_namespace.yaml'.format(DATA_DIR), base_fixture)

    deploy1 = lib.create_resource(
        '{}/case_28_nginx_deployment_1.yaml'.format(DATA_DIR), base_fixture)
    _, labels_1, _, _ = lib.get_deployment_details(
        name=deploy1['name'], namespace=ns['name'])

    svc1 = lib.create_resource('{}/case_28_nginx_service_1.yaml'.format(
        DATA_DIR), base_fixture)

    deploy2 = lib.create_resource(
        '{}/case_28_nginx_deployment_2.yaml'.format(DATA_DIR), base_fixture)
    _, labels_2, _, _ = lib.get_deployment_details(
        name=deploy2['name'], namespace=ns['name'])

    svc2 = lib.create_resource('{}/case_28_nginx_service_2.yaml'.format(
        DATA_DIR), base_fixture)

    deploy3 = lib.create_resource(
        '{}/case_28_nginx_deployment_3.yaml'.format(DATA_DIR), base_fixture)
    _, labels_3, _, _ = lib.get_deployment_details(
        name=deploy3['name'], namespace=ns['name'])

    base_fixture['delete_info'].reverse()

    policy = lib.create_resource('{}/case_28_policy_1.yaml'.format(
        DATA_DIR), base_fixture)
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    policy_2 = lib.create_resource('{}/case_28_policy_2.yaml'.format(
        DATA_DIR), base_fixture)
    policy_2_detail = lib.get_detail('SnatPolicy',
                                     name=policy_2['name'],
                                     namespace=policy_2['namespace'])

    snat_ips_1 = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids_1 = lib.get_snat_ids_for_service(svc1)

    snat_ips_2 = lib.get_allocated_snat_ips_for_service(svc2)
    snat_ids_2 = lib.get_snat_ids_for_service(svc2)

    snat_ips_3 = lib.get_allocated_snat_ips_from_policy(policy_2_detail)
    snat_ids_3 = lib.get_snat_ids_from_policy(policy_2_detail)

    lib.verify_null_mac_file_on_nodes()

    def _validate_deployment(deploy, labels, snat_ids, snat_ips, policy):
        kwargs = {'labels': ','.join(labels)}
        pods = kapi.get_detail('pod', namespace=ns['name'], **kwargs)

        for pod in pods['items']:
            pod_uid = pod['metadata']['uid']
            hostname = pod['spec']['nodeName']

            lib.validate_pod_ep_file(
                pod_uid, hostname, deploy['manifest_dir'], snat_ids=snat_ids)
            snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
            lib.validate_snat_file_on_host_for_snat_ips(
                hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

            lib.validate_traffic(
                deploy['manifest_dir'], pod['metadata']['name'], snat_ips[0],
                namespace=pod['metadata']['namespace'])

    _validate_deployment(deploy1, labels_1, snat_ids_1, snat_ips_1, policy)
    _validate_deployment(deploy2, labels_2, snat_ids_2, snat_ips_2, policy)
    _validate_deployment(deploy3, labels_3, snat_ids_3, snat_ips_3, policy_2)


@pytest.mark.usefixtures("clean_gen_templates")
def test_simple_snat_policy_with_dest_ip(base_fixture, gen_template_name):
    bb1 = lib.create_resource(
        '{}/case_29_busybox.yaml'.format(DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=bb1['name'])

    policy_input = get_policy_input('simple-snat-pol-with-dest-ips',
                                    {'test': 'case29-snatpolicy'},
                                    no_of_dest_ip=2)
    policy_temp = get_template(policy_input, gen_template_name)
    policy = lib.create_resource(policy_temp, base_fixture)

    policy_detail = lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(policy_detail)
    snat_ids = lib.get_snat_ids_from_policy(policy_detail)

    lib.verify_null_mac_file_on_nodes()

    lib.validate_pod_ep_file(
        uid, hostname, bb1['manifest_dir'], snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(
        hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    lib.validate_traffic_for_given_destination(bb1['manifest_dir'],
                                               bb1['name'],
                                               snat_ips[0],
                                               policy_input['dest_ips'])


@pytest.mark.usefixtures("clean_gen_templates")
def test_multiple_snat_policy_with_dest_ip(base_fixture, gen_template_name):
    bb1 = lib.create_resource(
        '{}/case_30_busybox.yaml'.format(DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=bb1['name'])

    policies = list()
    for pol_input in [
        {'name': 'snat-pol-with-dest-ips-case30-1',
         'labels': {'test-pol1': 'case30-snatpolicy-1'},
         'no_of_dest_ip': 2,
         'snat_ip': '10.3.50.50/32'},
        {'name': 'snat-pol-with-dest-ips-case30-2',
         'labels': {'test-pol2': 'case30-snatpolicy-2'},
         'no_of_dest_ip': None,
         'snat_ip': '10.3.39.39/32'}
    ]:
        policy_input = get_policy_input(
            pol_input['name'], pol_input['labels'],
            no_of_dest_ip=pol_input['no_of_dest_ip'],
            snat_ip=pol_input['snat_ip'])
        policy_temp = get_template(policy_input, gen_template_name)
        policy = lib.create_resource(policy_temp, base_fixture)
        policy_detail = lib.get_detail(
            'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

        snat_ips = lib.get_allocated_snat_ips_from_policy(policy_detail)
        snat_ids = lib.get_snat_ids_from_policy(policy_detail)

        policies.append(dict(policy=policy,
                             dest_ips=policy_input.get('dest_ips'),
                             snat_ips=snat_ips,
                             snat_ids=snat_ids))

    lib.verify_null_mac_file_on_nodes()

    lib.validate_pod_ep_file(
        uid, hostname, bb1['manifest_dir'], snat_ids=policies[0]['snat_ids'])
    snat_ip_info = lib.get_snat_ids(hostname, policies[0]['snat_ips'])
    lib.validate_snat_file_on_host_for_snat_ips(hostname,
                                                snat_ip_info,
                                                policy['manifest_dir'],
                                                policies[0]['snat_ips'])

    lib.validate_traffic_for_given_destination(bb1['manifest_dir'],
                                               bb1['name'],
                                               policies[0]['snat_ips'][0],
                                               policies[0]['dest_ips'])
    dest_ips = lib.get_dest_ips_from_config(count=3)
    lib.validate_traffic_for_given_destination(bb1['manifest_dir'],
                                               bb1['name'],
                                               policies[1]['snat_ips'][0],
                                               [dest_ips[2]])


@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_policy_at_scale_up_b(base_fixture, gen_template_name):
    kapi = KubeAPI()
    ns = lib.create_resource(
        '{}/scaleup_namespace.yaml'.format(DATA_DIR), base_fixture)

    deploy = lib.create_resource(
        '{}/scaleup_nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deploy['name'], namespace=ns['name'])

    policy_input = get_policy_input(
        'scale-up-snat-policy',
        {'test': 'scaleup-deployment'},
        namespace=ns['name'],
        snat_ip='10.3.49.49/32'
    )
    policy_temp = get_template(policy_input, gen_template_name)
    policy = lib.create_resource(policy_temp, base_fixture)
    snat_policy = kapi.get_detail('SnatPolicy', name=policy['name'],
                                  namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    kapi.exec_cli_cmd("kubectl scale --replicas=5 deployment %s -n %s" %
                      (deploy['name'], deploy['namespace']))
    lib.check_available_deployment_replicas(deploy['name'], ns['name'], 5)

    kwargs = {'labels': ','.join(labels), 'namespace': ns['name']}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        lib.validate_pod_ep_file(pod_uid,
                                 hostname,
                                 deploy['manifest_dir'],
                                 snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(hostname,
                                                    snat_ip_info,
                                                    policy['manifest_dir'],
                                                    snat_ips)

        lib.validate_traffic(
            deploy['manifest_dir'], pod['metadata']['name'], snat_ips[0],
            namespace=ns['name'])


@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_policy_at_scale_down_b(base_fixture, gen_template_name):
    kapi = KubeAPI()
    ns = lib.create_resource(
        '{}/scaledown_namespace.yaml'.format(DATA_DIR), base_fixture)

    deploy = lib.create_resource(
        '{}/scaledown_nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(
        name=deploy['name'], namespace=ns['name'])

    policy_input = get_policy_input(
        'scale-down-snat-policy',
        {'test': 'scaledown-deployment'},
        namespace=ns['name'],
        snat_ip='10.3.51.49/32'
    )
    policy_temp = get_template(policy_input, gen_template_name)
    policy = lib.create_resource(policy_temp, base_fixture)
    snat_policy = kapi.get_detail('SnatPolicy', name=policy['name'],
                                  namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    kapi.exec_cli_cmd("kubectl scale --replicas=2 deployment %s -n %s" %
                      (deploy['name'], deploy['namespace']))
    lib.check_available_deployment_replicas(deploy['name'], ns['name'], 2)
    lib.check_pods_count(ns['name'], 2, labels)

    kwargs = {'labels': ','.join(labels), 'namespace': ns['name']}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        lib.validate_pod_ep_file(pod_uid,
                                 hostname,
                                 deploy['manifest_dir'],
                                 snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(hostname,
                                                    snat_ip_info,
                                                    policy['manifest_dir'],
                                                    snat_ips)

        lib.validate_traffic(
            deploy['manifest_dir'], pod['metadata']['name'], snat_ips[0],
            namespace=ns['name'])


@pytest.mark.xfail
@pytest.mark.usefixtures("clean_gen_templates")
def test_snat_policy_for_rdconfig_update_b(base_fixture):
    kapi = KubeAPI()
    lib.create_resource(
        '{}/rdconfig_namespace.yaml'.format(DATA_DIR), base_fixture)
    pod = lib.create_resource('{}/rdconfig_validator_pod.yaml'.format(
        DATA_DIR), base_fixture)
    uid, _, hostname = lib.get_pod_details(name=pod['name'],
                                           namespace=pod['namespace'])

    policy = lib.create_resource('{}/rdconfig_snat_policy.yaml'.format(
        DATA_DIR), base_fixture)
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

    dest_ips = lib.get_dest_ips_from_config(count=2)

    kapi.patch('rdconfig',
               'routingdomain-config',
               {
                   'update_str': json.dumps(
                       [{"op": "add",
                         "path": "/spec/usersubnets",
                         "value": ["100.100.100.0/24"]}]),
                   'type': 'json'
               },
               namespace='aci-containers-system')
    try:
        lib.validate_traffic_for_given_destination(pod['manifest_dir'],
                                                   pod['name'],
                                                   snat_ips[0],
                                                   dest_ips=[dest_ips[1]],
                                                   # snat_policy['spec'][
                                                   #     'destIp'],
                                                   namespace=pod['namespace'])
    except Exception:
        raise
    finally:
        kapi.patch('rdconfig',
                   'routingdomain-config',
                   {
                       'update_str': json.dumps(
                           [{"op": "add",
                             "path": "/spec/usersubnets",
                             "value": []}]),
                       'type': 'json'
                   },
                   namespace='aci-containers-system')


def test_snat_policy_after_pod_deletion(base_fixture):
    """
    Create a Deployment and a Service. Service should point to the deployment.
    Create snat policy and apply it to the service.
    Do traffic validation before and after the pod deletion.
    """
    kapi = KubeAPI()

    # Creating deployment
    deployment = lib.create_resource(
        '{}/nginx_deployment.yaml'.format(DATA_DIR), base_fixture)
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'])

    # Creating service
    svc1 = lib.create_resource(
        '{}/nginx_service.yaml'.format(DATA_DIR), base_fixture)
    # Issue(VK) - According to Jayaram, the order may be issue with sept6
    # image. So first deleting service followed by deployment.
    base_fixture['delete_info'][0], base_fixture['delete_info'][1] = (
        base_fixture['delete_info'][1], base_fixture['delete_info'][0]
    )
    # Creating policy
    policy = lib.create_resource(
        '{}/sample_svc_snat_policy.yaml'.format(DATA_DIR), base_fixture)
    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids = lib.get_snat_ids_for_service(svc1)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
        validate_snat_apic_resource.test_apic(
            snat_ips, True, svc_namespace, svc1['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        # Validating traffic
        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0])

        # Deleting pod
        kapi.delete_object('pod', pod['metadata']['name'])

    # wait until new ngnix pod is re-spawned timeout 120 seconds
    lib.check_available_deployment_replicas(
        deployment['name'], deployment['namespace'], 3)

    # Getting the pods details after pods restart
    pods = kapi.get_detail('pod', **kwargs)
    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        # Re-validating traffic
        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0])


def test_snat_uuid_for_pod_and_hostagent_deletion(base_fixture):
    """
    Create a deployment and a service with some namespace. Associate service
    with deployment. Create a snat policy. Apply the policy to the service
    (deployment doesn't have policy association). Delete one of the pod of the
    deployment and hostagent pod from the same node at the same time.
    Observation: Sometimes snat-uuid is missing from ep file and issue is not
    recovered even after hostagent pod restart.
    """
    kapi = KubeAPI()
    # Creating namespace
    prefix = "test-uuid"
    ns_name = "ns-%s" % (prefix)
    ns_rsc = _get_input_for_namespace(ns_name)
    lib.create_resource_from_template(ns_rsc, base_fixture)

    # Creating a deployment and a service
    selector = {'app': 'nginx'}
    replicas = 3
    deployment_name = "nginx-deploy-%s" % (prefix)
    deployment_input = {'name': deployment_name,
                        'replicas': replicas,
                        'namespace': ns_name}
    svc_name = "nginx-svc-%s" % (prefix)
    svc_label = "label-%s" % (prefix)
    svc_input = {'name': svc_name,
                 'labels': {'test': svc_label},
                 'namespace': ns_name}
    depl_rsc, svc_rsc = _get_input_for_svc_and_deployment_with_replicas(
            deployment_input, svc_input, selector, replicas, )
    deployment = lib.create_resource_from_template(depl_rsc, base_fixture)
    service = lib.create_resource_from_template(svc_rsc, base_fixture)

    # Creating policy: keeping same policy_label as service label
    policy_name = "snatpolicy-%s" % (prefix)
    policy_label = "label-%s" % (prefix)
    policy_input = get_policy_input(policy_name, {'test': policy_label},
                                    ns_name, template='snat_policy.yaml')
    lib.create_resource_from_template(policy_input, base_fixture)

    # Verify and get the deleting pod info
    NO_OF_ROUNDS = 1
    snat_ids = lib.get_snat_ids_for_service(service)
    pods = kapi.get_detail('pod', namespace=ns_name)
    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        podname = pod['metadata']['name']

        if NO_OF_ROUNDS == 1:
            # Get a deployment pod and hostagent pod info of the same node
            pod_name = podname
            pod_host_ip = lib_helper.get_host_ip_of_pod(podname, ns_name)
            _hostagent_pods = lib_helper.get_pods_by_labels(
                              {'name': 'aci-containers-host'}, CRD_NAMESPACE)
            hostagent_pods = [pod_name for pod_name, host_ip, node_name in _hostagent_pods
                              if host_ip == pod_host_ip]
            NO_OF_ROUNDS += 1

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)

    # Delete a deployment pod and hostagent pod from the same node at sametime
    t1 = Thread(target=kapi.delete_object, args=('pod', pod_name, ns_name))
    t1.start()
    t2 = Thread(target=kapi.delete_object, args=('pod', hostagent_pods[0],
                CRD_NAMESPACE))
    t2.start()
    t1.join()
    t2.join()

    # wait until new ngnix pod is re-spawned, timeout 120 seconds
    lib.check_available_deployment_replicas(
        deployment['name'], deployment['namespace'], replicas)

    # Re-verify ep file
    pods = kapi.get_detail('pod', namespace=ns_name)
    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)


def test_snat_traffic_for_pod_and_hostagent_deletion(base_fixture):
    KAPI = KubeAPI()

    # Creating namespace
    prefix = "test-traffic"
    ns_name = "ns-%s" % (prefix)
    ns_rsc = _get_input_for_namespace(ns_name)
    ns = lib.create_resource_from_template(ns_rsc, base_fixture)

    # Creating a deployment and a service
    selector = {'test': 'acc-pytests', 'app': 'nginx'}
    replicas = 3
    deployment_name = "nginx-deploy-%s" % (prefix)
    deployment_input = {'name': deployment_name,
                        'replicas': replicas,
                        'namespace': ns_name}
    svc_name = "nginx-svc-%s" % (prefix)
    svc_input = {'name': svc_name,
                 'namespace': ns_name}
    depl_rsc, svc_rsc = _get_input_for_svc_and_deployment_with_replicas(
            deployment_input, svc_input, selector, replicas, )
    depl = lib.create_resource_from_template(depl_rsc, base_fixture)
    svc = lib.create_resource_from_template(svc_rsc, base_fixture)

    test_snat_policy = {
        'name': 'test-snat-policy',
        'namespace': ns_name,
        'template': 'snat_policy_with_dest_ip.yaml',
    }
    snat_policy = lib.create_resource_from_template(
        test_snat_policy, base_fixture)
    LOG.info("Resources created: ns, service with ngnix endpoint, snat policy")

    snat_ips = lib.get_allocated_snat_ips_for_service(svc)
    pods = lib_helper.get_pods_by_labels(selector, ns_name)
    NO_OF_ROUNDS = 1
    for podname, _, _ in pods:
        LOG.info(f"Validating traffic for pod: {podname}")
        lib.validate_traffic(
                depl['manifest_dir'], podname, snat_ips[0], namespace=ns_name)

        if NO_OF_ROUNDS == 1:
            # Get a deployment pod and hostagent pod info of the same node
            pod_name = podname
            pod_host_ip = lib_helper.get_host_ip_of_pod(podname, ns_name)
            _hostagent_pods = lib_helper.get_pods_by_labels(
                              {'name': 'aci-containers-host'}, CRD_NAMESPACE)
            hostagent_pods = [pod_name for pod_name, host_ip, node_name in _hostagent_pods
                              if host_ip == pod_host_ip]
            NO_OF_ROUNDS += 1

    t1 = Thread(target=KAPI.delete_object, args=('pod', pod_name, ns_name))
    t1.start()
    t2 = Thread(target=KAPI.delete_object, args=('pod', hostagent_pods[0],
                CRD_NAMESPACE))
    t2.start()
    t1.join()
    t2.join()
    LOG.info(f'Deleted {hostagent_pods[0]} & {pod_name}')

    # wait until new ngnix pod is re-spawned, timeout 120 seconds
    lib.check_available_deployment_replicas(
        depl['name'], depl['namespace'], replicas)

    snat_ips = lib.get_allocated_snat_ips_for_service(svc)
    pods = lib_helper.get_pods_by_labels(selector, ns_name)
    for podname, _, _ in pods:
        LOG.info(f"Re-Validating traffic for pod: {podname}")
        lib.validate_traffic(
                depl['manifest_dir'], podname, snat_ips[0], namespace=ns_name)


def test_snat_node_filter(base_fixture):
    kapi = KubeAPI()
    filtered_nodes = []

    # Add some labels on nodes
    nodes = lib.get_all('nodes')
    # Selecting a random node to filter out from redirect policy
    selected_node = random.choice(nodes['items'])

    kapi.apply_label(
            'nodes',
            True,
            None,
            'default',
            'node-role.kubernetes.io/test-label-1=',
            'node-role.kubernetes.io/test-label-2=',
            'node-role.kubernetes.io/test-label-3=',
            name=selected_node['metadata']['name']
        )

    filtered_nodes.append(selected_node['metadata']['name'])

    # Update config to match the master nodes
    acc_cm = kapi.get_detail('configmap', name='aci-containers-config',
                              namespace=CRD_NAMESPACE)
    acc_cm_controller_config = json.loads(acc_cm['data']['controller-config'])
    acc_cm_controller_config['node-snat-redirect-exclude'] = [
        {
            "group": "testmatch1",
            "labels": [
                "test-label-1",
                "test-label-2",
                "test-label-3"
            ]
        },
        {
            "group": "testmatch2",
            "labels": [
                "test-label-4",
                "test-label-5",
            ]
        }
    ]
    acc_cm['data']['controller-config'] = json.dumps(acc_cm_controller_config)
    lib.update_config_and_restart_controller(acc_cm, CRD_NAMESPACE)

    try:
        pod = lib.create_resource('{}/busybox.yaml'.format(DATA_DIR), base_fixture)
        uid, _, hostname = lib.get_pod_details(name=pod['name'])

        policy = lib.create_resource('{}/sample_snat_policy.yaml'.format(
            DATA_DIR), base_fixture)
        snat_policy = lib.get_detail(
            'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

        snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
        snat_ids = lib.get_snat_ids_from_policy(snat_policy)

        lib.verify_null_mac_file_on_nodes()

        lib.validate_pod_ep_file(
            uid, hostname, pod['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        if APIC_VALIDATION:
            validate_snat_apic_resource.test_apic(snat_ips, filtered_nodes=filtered_nodes)
        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0])

        # Remove config and check if nodes are not excluded.
        _remove_node_filter_config()

        if APIC_VALIDATION:
            validate_snat_apic_resource.test_apic(snat_ips, filtered_nodes=[])
        lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0])

    except Exception:
        raise
    finally:
        # Clean up node filter config and node labels
        _remove_node_filter_config()
        _remove_node_filter_node_labels(selected_node)

def _remove_node_filter_config():
    kapi = KubeAPI()
    # Remove the node filter config
    acc_cm = kapi.get_detail('configmap', name='aci-containers-config',
                              namespace=CRD_NAMESPACE)
    acc_cm_controller_config = json.loads(acc_cm['data']['controller-config'])
    if acc_cm_controller_config.get('node-snat-redirect-exclude'):
        del acc_cm_controller_config['node-snat-redirect-exclude']
        acc_cm['data']['controller-config'] = json.dumps(acc_cm_controller_config)
        lib.update_config_and_restart_controller(acc_cm, CRD_NAMESPACE)

def _remove_node_filter_node_labels(selected_node):
    kapi = KubeAPI()
    # Clean up node labels
    kapi.apply_label(
            'nodes',
            True,
            None,
            'default',
            'node-role.kubernetes.io/test-label-1-',
            'node-role.kubernetes.io/test-label-2-',
            'node-role.kubernetes.io/test-label-3-',
            name=selected_node['metadata']['name']
        )



def _get_input_for_namespace(name):
    return {
        'name': name,
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }


def _get_input_for_svc_and_deployment_with_replicas(
        deploy, svc, selectors, replicas, **kwargs):
    default_label = {'test': 'label-test'}
    deployment = {
        'name': deploy['name'],
        'kind': 'Deployment',
        'replicas': replicas,
        'namespace': deploy.get('namespace', 'default'),
        'template': 'nginx_deployment.yaml'
    }
    svc = {
        'name': svc['name'],
        'namespace': svc.get('namespace', 'default'),
        'labels': svc.get('labels', default_label),
        'template': 'nginx_service.yaml',
        'kind': 'Service',
        'lb_type': kwargs.get('lb_type', 'LoadBalancer')
    }
    if selectors:
        deployment['selector'] = selectors
        svc['selector'] = selectors
    return deployment, svc


def get_policy_input(name, labels, namespace='default',
                     snat_ip=None, no_of_dest_ip=None,
                     template='snat_policy_with_dest_ip.yaml'):
    if not isinstance(labels, dict):
        raise Exception("labels are expected in dict format")
    policy = {
        'name': name,
        'namespace': namespace,
        'labels': labels,
        'template': template
    }
    if no_of_dest_ip:
        policy['dest_ips'] = lib.get_dest_ips_from_config(no_of_dest_ip)
    # REVISIT(VK): check for multiple ips
    if snat_ip:
        policy['snat-ip'] = snat_ip
    return policy
