import os
from acc_pyutils.api import KubeAPI
import pytest
from tests.template_utils import env
from tests import lib, lib_helper, validate_snat_apic_resource
import yaml
from tests.input.cfg import ( APIC_VALIDATION, APIC_PROVISION_FILE, ACI_PREFIX )
from acc_pyutils import logger
from threading import Thread
from tests.vm_migration_helper import get_apic_aci

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')

class PropagatingThread(Thread):
    def run(self):
        self.exc = None
        try:
            self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self):
        super().join()
        if self.exc:
            raise self.exc

@pytest.mark.usefixtures("clean_gen_templates")
def test_epg_dataplane_egress(base_fixture, gen_template_name):
    kapi = KubeAPI()
    namespaces = ['ns1', 'ns2', 'ns3', 'ns4', 'ns5']
    epgs = []
    resources = {}
    cluster_info = get_clusters_info()
    apic = get_apic_aci()

    try:
        create_epg_in_parallel(base_fixture, gen_template_name, apic, cluster_info, namespaces, epgs)
        create_resources_in_parallel(base_fixture, namespaces, resources)

        for rsc in namespaces:
            #testing snat functionality
            policy = create_snat_policy(base_fixture, rsc)
            check_snat_for_pod(base_fixture, rsc, policy, resources[rsc]['pod'])
            check_snat_for_deployment(base_fixture, rsc, policy, resources[rsc]['deployment'])
            kapi.exec_cli_cmd('kubectl delete snatpolicy test-snatpolicysystem')
            check_snat_policy_for_service(base_fixture, rsc, resources[rsc]['deployment'], resources[rsc]['service'])
            kapi.exec_cli_cmd('kubectl delete snatpolicy test-servicesnatpolicy')
            check_multiple_external_ip_reachability(base_fixture, rsc, resources[rsc]['mtpod'])
            kapi.exec_cli_cmd('kubectl delete snatpolicy multi-target-snatpolicy')

    finally:
        for epg in epgs:
            apic.delete_epg(cluster_info['tenant'], cluster_info['app_profile'], epg)

def create_epg_in_parallel(base_fixture, gen_template_name, apic, cluster_info, namespaces, epgs):
    threads = []

    for ns in namespaces:
        thread = PropagatingThread(target=create_epg_and_annotate_ns, args=(base_fixture, gen_template_name, apic, cluster_info, ns, epgs))
        threads.extend([thread])

    for thread in threads:
        thread.start()

    for thread in threads:
        try:
            thread.join()
        except Exception as e:
            LOG.error(f"Thread {thread} raised an exception: {e}")
            assert False, ("Thread execution failed")

def create_epg_and_annotate_ns(base_fixture, gen_template_name, apic, cluster_info, ns, epgs):
    """ Create epg and annotate to the namespace"""
    create_epg(apic, ns, cluster_info)
    epgs.append(ns)

    """Creating annotated namespace"""
    template = 'annotated_ns.yaml'
    namespace = {
        'name': ns,
        'tenant': cluster_info['tenant'],
        'app_profile': cluster_info['app_profile'],
        'epg': ns
    }
    template = env.get_template(template)
    rend_temp = template.render(input=namespace)
    temp_name = gen_template_name(namespace['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    lib.create_resource(temp_name, base_fixture, namespace['name'])


def create_resources_in_parallel(base_fixture, namespaces, resources):
    threads = []

    for ns in namespaces:
        resources[ns] = {}
        thread_nw_policy = PropagatingThread(target=create_nw_policy, args=(base_fixture, ns))
        thread_pod = PropagatingThread(target=create_pod, args=(base_fixture, ns, resources))
        thread_deployment = PropagatingThread(target=create_deployment, args=(base_fixture, ns, resources))
        thread_service = PropagatingThread(target=create_service, args=(base_fixture, ns, resources))
        thread_mtpod = PropagatingThread(target=create_mt_pod, args=(base_fixture, ns, resources))

        threads.extend([thread_nw_policy, thread_pod, thread_deployment, thread_service, thread_mtpod])

    for thread in threads:
        thread.start()

    for thread in threads:
        try:
            thread.join()

        except Exception as e:
            LOG.error(f"Thread {thread} raised an exception: {e}")
            assert False, ("Thread execution failed")

def get_clusters_info():

    apic_provision = lib_helper.get_apic_provision_input(APIC_PROVISION_FILE)
    # get cluster info from acc provison input file
    cluster_info = lib_helper.get_resource_details_from_acc_provision_input_file(apic_provision)
    return cluster_info

def create_epg(apic, name, cluster_info):
    '''
    Creates the epg

    Args:
    apic(obj): apic object to access apic
    name(str): epg name
    cluster_info(dict): apic cluster info
    '''

    tenant = cluster_info['tenant']
    app_profile = cluster_info['app_profile']
    kube_naming_used = cluster_info['use_kube_naming_convention']

    if kube_naming_used:
        source_epg_name = 'kube-default'
    else:
        source_epg_name = ACI_PREFIX + '-default'

    apic.create_epg(tenant, app_profile, name, source_epg_name)

    LOG.info('CREATED EPG %s IN TENANT %s', name, tenant)

def create_nw_policy(base_fixture, ns):
    networkpolicy_manifest_path = '{}/namespace_networkpolicy.yaml'.format(DATA_DIR)
    with open(networkpolicy_manifest_path, 'r') as file:
        yamls = yaml.safe_load_all(file)
        yamls = list(yamls)

    for manifest in yamls:
        manifest['metadata']['namespace'] = ns
        parts = manifest['metadata']['name'].split('-')
        manifest_name = parts[-1]
        lib_helper.dump_template(f"{manifest['metadata']['name']}-{ns}", str(manifest))
        lib.create_resource(f"{manifest['metadata']['name']}-{ns}", base_fixture, f"{manifest_name}-{ns}")

def create_pod(base_fixture, ns, resources):

    pod_manifest_path = '{}/busybox.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = ns
    lib_helper.dump_template(f"{pod_manifest['metadata']['name']}-{ns}", str(pod_manifest))
    pod = lib.create_resource(f"{pod_manifest['metadata']['name']}-{ns}", base_fixture, f"{pod_manifest['metadata']['name']}-{ns}")
    resources[ns]['pod'] = pod

def create_deployment(base_fixture, ns, resources):

    deployment_manifest_path = '{}/nginx_deployment.yaml'.format(DATA_DIR)
    with open(deployment_manifest_path, 'r') as file:
        deployment_manifest = yaml.safe_load(file)

    deployment_manifest['metadata']['namespace'] = ns
    lib_helper.dump_template(f"{deployment_manifest['metadata']['name']}-{ns}", str(deployment_manifest))
    deployment = lib.create_resource(f"{deployment_manifest['metadata']['name']}-{ns}", base_fixture, f"{deployment_manifest['metadata']['name']}-{ns}")
    resources[ns]['deployment'] = deployment

def create_service(base_fixture, ns, resources):

    svc_manifest_path = '{}/nginx_service.yaml'.format(DATA_DIR)
    with open(svc_manifest_path, 'r') as file:
        svc_manifest = yaml.safe_load(file)

    svc_manifest['metadata']['namespace'] = ns
    lib_helper.dump_template(f"{svc_manifest['metadata']['name']}-{ns}", str(svc_manifest))
    svc1 = lib.create_resource(f"{svc_manifest['metadata']['name']}-{ns}", base_fixture, f"{svc_manifest['metadata']['name']}-{ns}")
    resources[ns]['service'] = svc1

def create_mt_pod(base_fixture, ns, resources):

    pod_manifest_path = '{}/busybox_multi_target.yaml'.format(DATA_DIR)
    with open(pod_manifest_path, 'r') as file:
        pod_manifest = yaml.safe_load(file)

    pod_manifest['metadata']['namespace'] = ns
    lib_helper.dump_template(f"{pod_manifest['metadata']['name']}-{ns}", str(pod_manifest))
    pod = lib.create_resource(f"{pod_manifest['metadata']['name']}-{ns}", base_fixture, f"{pod_manifest['metadata']['name']}-{ns}")
    resources[ns]['mtpod'] = pod


def create_snat_policy(base_fixture, ns):
    snat_manifest_path = '{}/sample_snat_policy.yaml'.format(DATA_DIR)
    with open(snat_manifest_path, 'r') as file:
        snat_manifest = yaml.safe_load(file)

    snat_manifest['metadata']['name'] = 'test-snatpolicysystem'
    snat_manifest['metadata']['namespace'] = ns
    snat_manifest['spec']['selector']['namespace'] = ns
    lib_helper.dump_template(snat_manifest['metadata']['name'], str(snat_manifest))
    policy = lib.create_resource(snat_manifest['metadata']['name'], base_fixture)
    return policy

def check_snat_for_pod(base_fixture, ns, policy, pod):
    LOG.info('Testing SNAT for Pod . . . ')

    uid, _, hostname = lib.get_pod_details(name=pod['name'], namespace=ns)

    snat_policy = lib.get_detail('SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)


    lib.validate_pod_ep_file(uid, hostname, pod['manifest_dir'],snat_ids=snat_ids)
    snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
    lib.validate_snat_file_on_host_for_snat_ips(hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

    lib.validate_traffic(pod['manifest_dir'], pod['name'], snat_ips[0], namespace=ns)

def check_snat_for_deployment(base_fixture, ns, policy, deployment):
    kapi = KubeAPI()
    LOG.info('Testing SNAT for Deployment . . . ')
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'], namespace=ns)

    snat_policy = lib.get_detail('SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_from_policy(snat_policy)
    snat_ids = lib.get_snat_ids_from_policy(snat_policy)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        validate_snat_apic_resource.test_apic(snat_ips)

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=ns, **kwargs)

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
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0], namespace=ns)


def check_snat_policy_for_service(base_fixture, ns, deployment, svc1):
    LOG.info('Testing SNAT for Service . . . ')
    kapi = KubeAPI()

    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'], namespace=ns)


    snat_manifest_path = '{}/sample_svc_snat_policy.yaml'.format(DATA_DIR)
    with open(snat_manifest_path, 'r') as file:
        snat_manifest = yaml.safe_load(file)

    snat_manifest['spec']['selector']['namespace'] = ns
    lib_helper.dump_template(snat_manifest['metadata']['name'], str(snat_manifest))
    policy = lib.create_resource(snat_manifest['metadata']['name'], base_fixture)

    lib.get_detail(
        'SnatPolicy', name=policy['name'], namespace=policy['namespace'])

    snat_ips = lib.get_allocated_snat_ips_for_service(svc1)
    snat_ids = lib.get_snat_ids_for_service(svc1)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc1['namespace'] if "namespace" in svc1 else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True, svc_namespace, svc1['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=ns, **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']

        lib.validate_pod_ep_file(
            pod_uid, hostname, deployment['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            deployment['manifest_dir'], pod['metadata']['name'], snat_ips[0], namespace=ns)

def check_multiple_external_ip_reachability(base_fixture, ns, pod):
    LOG.info('Testing SNAT for Multiple external ip reachability . . . ')

    uid, _, hostname = lib.get_pod_details(name=pod['name'], namespace=ns)

    snat_manifest_path = '{}/multi_target_snat_policy.yaml'.format(DATA_DIR)
    with open(snat_manifest_path, 'r') as file:
        snat_manifest = yaml.safe_load(file)

    snat_manifest['spec']['selector']['namespace'] = ns
    lib_helper.dump_template(snat_manifest['metadata']['name'], str(snat_manifest))
    policy = lib.create_resource(snat_manifest['metadata']['name'], base_fixture)

    snat_policy = lib.get_detail('SnatPolicy',name=policy['name'],namespace=policy['namespace'])

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
                         verify_multiple_targets=True, namespace=ns)
