import os, time
from acc_pyutils.api import KubeAPI
from tests import lib, lib_helper, validate_snat_apic_resource
import yaml
from tests.input.cfg import APIC_VALIDATION, EXTERNAL_IP_POOL
from acc_pyutils import logger
from threading import Thread
from tests.test_datapath import _get_input_for_svc_and_deployment, \
        check_traffic_from_pod_to_svc, \
        check_traffic_from_pod_to_svc_endpoint, \
        _create_common_resources, \
        _delete_common_resources, \
        _get_input_for_daemonset, \
        _get_input_for_namespace

LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
DEFAULT_INTERVAL = 10
DEFAULT_TIMEOUT = 30 * 60
SVC_TEST_NS = "test-dp-svc-ns"

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

def create_resources_and_check_datapath_connectivity(
        base_fixture, namespaces=['test-dp-ns'], **kwargs):
    """ Create resources, run datapath test and delete resources
    This test verify below test case
    1. Pod to Pod
    2. Pod to Service
    3. SNAT for Deployment
    4. Pod to Ingress
    """
    resources = dict()
    try:
        LOG.info("Create resources and run datapath test")
        create_datapath_resources_in_parallel(base_fixture, namespaces, resources, **kwargs)
        check_datapath_connectivity(base_fixture, namespaces, resources, **kwargs)
    except Exception as ex:
        LOG.warning("Datapath Traffic test failed : %s" % ex)
        raise
    finally:
        delete_datapath_resources(base_fixture, resources)

def create_datapath_resources_in_parallel(base_fixture, namespaces, resources, **kwargs):
    """ Create Namespace, test Pod, test Deployment, SNAT Delpoyment, SNAT Policy,
    Service and Deployment for Service test in parallel
    """
    nodename = kwargs.get("nodename", None)
    max_pod = kwargs.get("max_pod", False)
    snat = kwargs.get("snat", True)

    threads = list()
    for ns in namespaces:
        resources[ns] = dict()
        if ns != 'default':
            ns_input = _get_input_for_namespace(ns)
            resources[ns]['namespace'] = lib.create_resource_from_template(ns_input, base_fixture)
        thread_pod = PropagatingThread(target=create_test_pod, args=(
            base_fixture, "test-pod", ns, resources, nodename))
        thread_pods = PropagatingThread(target=create_resource_from_manifest, args=(
            base_fixture, "pods", ns, resources, nodename))
        thread_ds = PropagatingThread(target=create_ds, args=(base_fixture, "test-ds", ns, resources))
        thread_deployment_svc = PropagatingThread(target=create_deployment_and_svc, args=(
            base_fixture, "test-deploy", "test-svc", ns, resources, nodename))
        threads.extend([thread_pod, thread_pods, thread_ds, thread_deployment_svc])
        if snat is True:
            thread_snat_pods_svc_policy = PropagatingThread(target=create_snat_svc_policy_test_resource, args=(
                base_fixture, ns, resources, nodename))
            threads.append(thread_snat_pods_svc_policy)

    # Create additional namespace for cross namespace svc test
    resources[SVC_TEST_NS] = dict()
    ns_input = _get_input_for_namespace(SVC_TEST_NS)
    resources[SVC_TEST_NS]['namespace'] = lib.create_resource_from_template(ns_input, base_fixture)    
    if max_pod is True:
        # Created Deployment with max_available_pods - 20, so that other resources in test are created
        replicas = lib.get_per_node_max_pod(nodename) - lib.get_pod_running_on_node(nodename) - 20
    else:
        replicas = 2
    thread_deployment_svc_1 = PropagatingThread(target=create_deployment_and_svc, args=(
        base_fixture, "test-deploy-1", "test-svc-1", SVC_TEST_NS, resources, nodename, replicas))
    threads.append(thread_deployment_svc_1)
    for thread in threads:
        thread.start()
    for thread in threads:
        try:
            thread.join()
        except Exception as e:
            LOG.error(f"Thread {thread} raised an exception: {e}")
            assert False, ("Thread execution failed")

def check_datapath_connectivity(base_fixture, namespaces, resources, **kwargs):
    """ Tests below test cases in parallel as part of datapath connectivity test
    1. Pod to Pod
    2. Pod to Service
    3. SNAT for Deployment
    4. Pod to Ingress
    """
    nodename = kwargs.get("nodename", None)
    pod_to_pod = kwargs.get("pod_to_pod", True)
    pod_to_svc = kwargs.get("pod_to_svc", True)
    snat = kwargs.get("snat", True)
    pod_to_ext = kwargs.get("pod_to_ext", False)
    ext_svc_traffic = kwargs.get("ext_svc_traffic", True)
    pod_to_svc_curl = kwargs.get("pod_to_svc_curl", True)

    threads = list()
    for ns in namespaces:
        if pod_to_pod is True:
            thread_ew_traffic = PropagatingThread(target=check_traffic_between_pods, args=(
                resources, ns, nodename))
            threads.append(thread_ew_traffic)
        if pod_to_svc is True:
            thread_pod_to_svc = PropagatingThread(target=verify_pod_to_svc, args=(
                resources, ns, nodename, ext_svc_traffic, pod_to_svc_curl))
            threads.append(thread_pod_to_svc)
        if snat is True:
            thread_snat_svc_policy = PropagatingThread(target=check_snat_policy_for_service_with_pods, args=(
                resources[ns]['snat_svc_policy'], resources[ns]['snat_svc_pods'], resources[ns]['snat_svc'], ns, nodename))
            threads.append(thread_snat_svc_policy)
        if pod_to_ext is True:
            pods_ds = lib_helper.get_pods_by_labels(
                resources[ns]['ds']['labels'], namespace=ns)
            thread_pod_to_ext_dst = PropagatingThread(target=verify_pod_to_ext_dest, args=(
                base_fixture, pods_ds, ns))
            threads.append(thread_pod_to_ext_dst)
        
    for thread in threads:
        thread.start()
    for thread in threads:
        try:
            thread.join()
        except Exception as e:
            LOG.error(f"Thread {threads} raised an exception: {e}")
            assert False, "Test Failed"
        LOG.info(f"{thread} Traffic Test Passed")

def delete_datapath_resources(base_fixture, resources):
    """ Delete resources created for datapath testing """
    kapi = KubeAPI()
    tmp_del_info = base_fixture.get('delete_info', [])
    for namespace, resource in resources.items():
        LOG.info("Deleting resources in namespce %s" % namespace)
        for k, v in resource.items():
            kind = v['kind']
            if kind == 'Namespace':
                LOG.debug("Namespace will be deleted at end")
                continue
            elif kind != 'Pod':
                name = v['name']
            else:
                test_pod = lib_helper.get_pods_by_labels(
                    resource['pod']['labels'], namespace=namespace)
                if not test_pod:
                    continue
                name = test_pod[0][0]
            LOG.info("Deleting kind %s name %s" %(kind, name))
            try:
                kapi.delete_object(kind, name, namespace)
                del_info = (v['add_label'], v['manifest_dir'])
                if del_info in tmp_del_info:
                    LOG.info("Removing %s" % str(del_info))
                    tmp_del_info.remove(del_info)
            except Exception as e:
                LOG.warning(f"Failed to delete: {e}")
                pass
        if namespace != 'default':
            try:
                LOG.info("Deleting namespace %s" % (namespace))
                kapi.delete_object('namespace', namespace, timeout=240)
                v = resource['namespace']
                del_info = (v['add_label'], v['manifest_dir'])
                if del_info in tmp_del_info:
                    LOG.debug("Removing %s" % str(del_info))
                    tmp_del_info.remove(del_info)
            except Exception as e:
                LOG.warning(f"Failed to delete: {e}")
                pass

    # Update delete_info 
    base_fixture['delete_info'] = tmp_del_info
    resources.clear()
    LOG.debug(base_fixture)        

def create_test_pod(base_fixture, name, ns, resources, nodename):
    """ Create a Test Pod """
    test_pod_input = {'name': name,
                     'labels': {'name': name},
                     'namespace' : ns,
                     'node' : nodename,
                     'image': 'noiro-quay.cisco.com/noiro/alpine-utils:latest'} 
    test_pod = lib.create_pod(test_pod_input, base_fixture)
    resources[ns]['pod'] = test_pod
    return test_pod

def create_deployment_and_svc(base_fixture, dep_name, svc_name, ns, resources, nodename, replicas=2):
    """ Create a Deployment and Service """
    deploy_in = {'name': dep_name, 'namespace': ns,
                 'label': {'app': dep_name}, 'node' : nodename}
    svc_in = {'name': svc_name, 'namespace': ns}
    selector = {'name': dep_name}
    deploy, svc = _get_input_for_svc_and_deployment(deploy_in, svc_in, selector, replicas=replicas)
    resources[ns]['deployment'] = lib.create_resource_from_template(deploy, base_fixture)
    resources[ns]['svc'] = lib.create_resource_from_template(svc, base_fixture)
    resources[ns]['deployment'].update({'labels' : selector})
    resources[ns]['deployment']['replicas'] = replicas
    resources[ns]['svc'].update({'labels' : selector})

def create_ds(base_fixture, name, ns, resources, selector=None):
    """ Create a Daemonset """
    if selector is None:
        ds_selector = {'name': name}
    else:
        ds_selector = selector
    daemonset = _get_input_for_daemonset("test-ds", ds_selector, namespace=ns, runonmaster=True)
    resources[ns]['ds'] = lib.create_resource_from_template(daemonset, base_fixture)
    resources[ns]['ds'].update({'labels' : ds_selector})

def create_snat_svc_policy_test_resource(base_fixture, ns, resources, nodename):
    create_resource_from_manifest(base_fixture, "snat_svc_pods", ns, resources, nodename)
    create_resource_from_manifest(base_fixture, "snat_svc", ns, resources)
    create_resource_from_manifest(base_fixture, "snat_svc_policy", ns, resources)

def create_resource_from_manifest(base_fixture, type, ns, resources, nodename=None):
    """ Create resources from manifest based on type(snat_svc_pods, snat_policy, snat_svc, snat_svc_policy, pods)"""
    replicas = 1
    if type == "snat_svc_pods":
        if lib.is_valid_cluster_for_snat_ds_test():
            name = "test-snat-svc-ds"
            manifest_path = '{}/nginx_ds.yaml'.format(DATA_DIR)
        else:
            name = "test-snat-svc-deploy"
            manifest_path = '{}/nginx_deployment.yaml'.format(DATA_DIR)
            if nodename is not None:
                max_node = lib.get_node_limit_for_snat_op_from_configmap()
                nodes = lib.get_all_nodes_count_with_ready_state()
                replicas = min(max_node, nodes)
    elif type == "snat_policy":
        name = "test-snatpolicy"
        manifest_path = '{}/sample_snat_policy.yaml'.format(DATA_DIR)
    elif type == "snat_svc":
        name = "test-snat-svc"
        manifest_path = '{}/nginx_service.yaml'.format(DATA_DIR)
    elif type == "snat_svc_policy":
        name = "test-snat-svc-policy"
        manifest_path = '{}/sample_svc_snat_policy.yaml'.format(DATA_DIR)
    elif type == "pods":
        name = "test-pod-deploy"
        manifest_path = '{}/node_scale_apline_deployment.yaml'.format(DATA_DIR)
    else:
        assert False, f"Invalid type {type}"

    with open(manifest_path, 'r') as file:
        manifest = yaml.safe_load(file)
    
    manifest['metadata']['name'] = name
    manifest['metadata']['namespace'] = ns
    kind = manifest.get('kind', '')
    if  kind in ("SnatPolicy") :
        manifest['spec']['selector']['namespace'] = ns
    elif kind == "Deployment":
        manifest['spec']['replicas'] = replicas
    if  nodename is not None and (kind in ("Deployment", "Pod")):
        LOG.info(f'Deploying pods on the node {nodename}')
        manifest['spec']['template']['spec']['nodeName'] = nodename
       
    lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
    resources[ns][type] = lib.create_resource(manifest['metadata']['name'], base_fixture)

def get_test_pods(resources, namespace, nodename):
    """ Get src and dest test pods for testing """
    pods_ds = lib_helper.get_pods_by_labels(
        resources[namespace]['ds']['labels'], namespace=namespace)
    pods_dep = lib_helper.get_pods_by_labels(
        resources[namespace]['deployment']['labels'], namespace=namespace)
    test_pods_dep =  lib_helper.get_pods_by_labels(
        resources[namespace]['pods']['labels'], namespace=namespace)
    test_pod = lib_helper.get_pods_by_labels(
        resources[namespace]['pod']['labels'], namespace=namespace)
    src_test_pods = test_pod + test_pods_dep
    dest_pods = pods_ds + pods_dep
    if nodename is not None:
        src_test_pods_node = [_pod for _pod in src_test_pods if _pod[2] == nodename]
        if not src_test_pods_node:
            LOG.debug("No Test pod found on node %s testing with other nodes pod" % (nodename))
            src_test_pods_node = src_test_pods
        src_test_pods = src_test_pods_node
        dest_pods = [_pod for _pod in dest_pods if _pod[2] == nodename]

    LOG.info("Src Test pods %d Dest Pod %d found" % (len(src_test_pods), len(dest_pods)))
    return src_test_pods, dest_pods

def check_traffic_between_pods(resources, namespace, nodename):
    """ Verify EW traffic(Pod-Pod) """
    src_test_pods, dest_pods = get_test_pods(resources, namespace, nodename)
    if len(src_test_pods) == 0 or  len(dest_pods) == 0:
        LOG.error("Src Test pods %d Dest Pod %d found" % (len(src_test_pods), len(dest_pods)))
        assert False, ("No pod found for testing!!!!")

    LOG.info('Verifying ping between pods. . . ')
    result = {'status' : list(), 'fail' : list(), 'pass' : list()}
    for _pod in src_test_pods:
        p_name = _pod[0]
        if not lib.is_pod_running(p_name, namespace=namespace):
            LOG.warning("Tester pod %s not running test will fail continue" % p_name)
            result['status'].append(False)
            result['fail'].append((_pod, dest_pods))
            continue
        for dest_pod in dest_pods:
            LOG.debug("SP %s : %s DP %s" %(p_name, _pod[2], dest_pod))
            if not lib.is_pod_running(dest_pod[0], namespace=namespace):
                LOG.warning("Dest pod not Running Test will fail!")
                result['status'].append(False)
                result['fail'].append((_pod, dest_pod))
                continue
            try:
                lib_helper.check_ping_from_pod(p_name, namespace, dest_pod[1])
                # Test Passed
                result['status'].append(True)
                result['pass'].append((_pod, dest_pod))
            except Exception as ex:
                LOG.warning("Connectivity test failed : %s" % ex)
                result['status'].append(False)
                result['fail'].append((_pod, dest_pod))
                #continue to test next pod
                pass
    dump_connectivity_test_result(result) 
    assert all(result['status']), "Test Failed" 
    return all(result['status'])

def verify_pod_to_svc(resources, namespace, nodename, ext_svc_traffic, pod_to_svc_curl):
    """ Verify Pod-Service Traffic  
        
    Check service, endpoint and ext traffic for below case 
        Case 1. service deployment in the test pod namespace(same ns)
        Case 2. service deployment in the different namespace(cross ns)
    """
    if nodename is not None:
        # Run from specific node 
        _, pods_ds = get_test_pods(resources, namespace, nodename)
    else :
        pods_ds = lib_helper.get_pods_by_labels(
            resources[namespace]['ds']['labels'], namespace=namespace)
    LOG.info('Verifying pod to svc traffic. . . ')
    svc_in_0 = resources[namespace]['svc']
    svc_in_1 = resources[SVC_TEST_NS]['svc']
    for _pod in pods_ds:
        try:
            LOG.info("Test Pod : %s" % str(_pod))
            _pod_in = {'name': _pod[0], 'kind': 'pod', 'namespace': namespace}
            for svc_in in [svc_in_0, svc_in_1]:
                check_traffic_from_pod_to_svc(_pod_in, svc_in)
                check_traffic_from_pod_to_svc_endpoint(_pod_in, svc_in)
                if pod_to_svc_curl:
                    check_pod_to_svc_curl(_pod_in, svc_in)
        except Exception as e:
            LOG.error('verify pod to svc failed: %s' % e)
            raise

    # Verify external SVC traffic
    if ext_svc_traffic:
        for svc_in in [svc_in_0, svc_in_1]:
            verify_ext_svc_traffic(svc_in['name'], svc_in['namespace'])


def verify_ext_svc_traffic(svc_name, svc_ns):
    svc = lib_helper.get_svc_detail(svc_name, svc_ns)
    passed = failed = 0
    for ip in EXTERNAL_IP_POOL:
        try:
            lib_helper.connect_to_lbs(ip, svc, svc_ns, 60)
            passed = passed + 1
        except Exception as ex:
            LOG.warning("connect_to_lbs failed for ext_ip %s" % ip)
            failed = failed + 1
            pass

    LOG.info("connect_to_lbs Passed %d Failed %d", passed, failed)
    assert passed != 0, ("Failed to connect to LB svc %s namespace %s", svc_name, svc_ns)
    return passed, failed

#TODO : Optimize this test
def verify_pod_to_ext_dest(base_fixture, pods, ns):
    """ Verify Pod-Ingress """
    kapi = KubeAPI()
    router_default = None
    try:
        ocp_route = _create_common_resources(base_fixture)

        router_default = lib.get_detail('service', 'router-default',
                                        'openshift-ingress')
        router_sharded = lib.get_detail('service', 'router-sharded',
                                        'openshift-ingress')
        lib.check_os_route_status(ocp_route['name'], ocp_route['namespace'])
        route_detail = lib.get_detail('route', ocp_route['name'], ocp_route[
            'namespace'])

        LOG.info('default IP - %s' % router_default['status']['loadBalancer'][
            'ingress'][0]['ip'])
        LOG.info('Route - %s' % route_detail['status']['ingress'][0]['host'])
        LOG.info('sharded IP - %s' % router_sharded['status']['loadBalancer'][
            'ingress'][0]['ip'])

        lib.update_host_file("%s  %s" % (
            router_default['status']['loadBalancer']['ingress'][0]['ip'],
            route_detail['status']['ingress'][0]['host']), "add")
        for _pod in pods:
            try:
                cmd = 'curl -k https://%s' % route_detail['status']['ingress'][0]['host']
                kapi.kexec(_pod[0], cmd, interpreter='sh -c', namespace=ns)
            except Exception as e:
                LOG.error('verify pod to ext dest failed for pod %s: %s' % (_pod, e))
                raise
    finally:
        try:
            _delete_common_resources(base_fixture)
        except Exception as e:
            LOG.warning("Deletion of resources failed. %s" % e)

        if router_default is not None:
            try:
                lib.update_host_file("%s  %s" % (
                    router_default['status']['loadBalancer']['ingress'][0]['ip'],
                    route_detail['status']['ingress'][0]['host']),
                                     "delete")
            except KeyError:
                pass

def check_snat_for_deployment(policy, deployment, ns):
    """ Verify SNAT for Deployment"""
    kapi = KubeAPI()
    LOG.info('Testing SNAT for Deployment . . . ')
    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'], namespace=ns)
    snat_policy = lib.get_detail('SnatPolicy', name=policy['name'], namespace=ns)
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

def check_snat_policy_for_service_with_pods(policy, snat_pods, svc, ns, nodename=None):

    """ Verify SNAT Policy for service with DaemonSet or Deployment"""
    kapi = KubeAPI()
    kind = snat_pods.get('kind', '')
    LOG.info('Testing SNAT Policy for service with %s. . . ' % kind)
    if kind == 'DaemonSet':
        labels = lib.get_ds_details(name=snat_pods['name'], namespace=ns)
    elif kind == 'Deployment':
        _, labels, _, _ = lib.get_deployment_details(name=snat_pods['name'], namespace=ns)
    else:
        assert False, ("Invalid Kind : %s for SNAT Policy Test" % kind)

    snat_policy = lib.get_detail('SnatPolicy', name=policy['name'], namespace=ns)
    LOG.info(snat_policy)

    snat_ips = lib.get_allocated_snat_ips_for_service(svc)
    snat_ids = lib.get_snat_ids_for_service(svc)

    lib.verify_null_mac_file_on_nodes()

    if APIC_VALIDATION:
        svc_namespace = svc['namespace'] if "namespace" in svc else "default"
        validate_snat_apic_resource.test_apic(snat_ips, True,
                                              svc_namespace, svc['name'])

    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=ns, **kwargs)

    for pod in pods['items']:
        pod_uid = pod['metadata']['uid']
        hostname = pod['spec']['nodeName']
        if nodename is not None and nodename != hostname:
            # Run only on specified node
            continue
        lib.validate_pod_ep_file(
            pod_uid, hostname, snat_pods['manifest_dir'], snat_ids=snat_ids)
        snat_ip_info = lib.get_snat_ids(hostname, snat_ips)
        lib.validate_snat_file_on_host_for_snat_ips(
            hostname, snat_ip_info, policy['manifest_dir'], snat_ips)

        lib.validate_traffic(
            snat_pods['manifest_dir'], pod['metadata']['name'], snat_ips[0], namespace=ns)


def get_dest_pod_on_same_src_pod(p_name, result_t):
    """ Helper function for dump_connectivity_test_result """
    pod_list = list()
    for src, dest in result_t:
        if p_name in src[0]:
            if dest not in pod_list:
                pod_list.append(dest)
    return pod_list

def parse_result(result_t):
    """ Helper function for dump_connectivity_test_result """
    result_map = list()
    src_pod = list()
    for src, dest in result_t:
        if src[0] in src_pod:
            continue
        other_pods = get_dest_pod_on_same_src_pod(src[0], result_t)
        result_map.append((src, other_pods))
        src_pod.append(src[0])
    return result_map

def dump_connectivity_test_result(result):
    """ Dump Connectivity Test Summary """
    LOG.info("Connectivity Test %s" % 
                "Passed" if all(result['status']) else "Failed!")
    fail_list =  parse_result(result['fail'])
    pass_list = parse_result(result['pass'])
    for src, dest in fail_list:
        LOG.warning("Fail : %s --> %s" % (src, dest))
    for src, dest in pass_list:
        LOG.info("Pass : %s --> %s" % (src, dest))

def check_for_basic_traffic(resources, namespace, nodename=None, timeout=DEFAULT_TIMEOUT):
    """ Check for connectivity b/w pods using ping """ 
    LOG.info("Max test time %d Sec.." % timeout)
    failed_count = 0
    max_time = time.time() + timeout
    start_time = time.time()
    traffic_resumed = False
    while time.time() < max_time:
        try:
            traffic_resumed = check_traffic_between_pods(resources, namespace, nodename)
            LOG.debug("Traffic resumed %r!!!" % traffic_resumed)
            break
        except Exception as ex:
            failed_count = failed_count + 1
            pass
        time.sleep(DEFAULT_INTERVAL)
    end_time = time.time()
    time_diff = int(end_time - start_time) if failed_count > 0 else 0
    LOG.info("Traffic Resumed : %r in %d Sec..." % (traffic_resumed, time_diff))
    return traffic_resumed, time_diff

def create_client_pod_for_svc_curl(base_fixture, nodename, ns, resources):
    manifest_path = '{}/alpine_pod_ns1.yaml'.format(DATA_DIR)
    with open(manifest_path, 'r') as file:
        manifest = yaml.safe_load(file)
    manifest['metadata']['namespace'] = ns
    if nodename is not None:
        manifest['spec']['nodeName'] = nodename

    lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
    pod = lib.create_resource(manifest['metadata']['name'], base_fixture)
    resources[ns]['pod'] = pod

#TODO Add test for Network Policy
def create_reboot_test_resources(base_fixture, gen_template_name, node, ns):
    kapi = KubeAPI()

    # We will check for the available number of pods that can be deployed on the node
    nodes = kapi.get_detail('nodes')
    for knode in nodes['items']:
        if knode['metadata']['name'] == node:
            max_pods = int(knode['status']['allocatable']['pods'])
    already_running_pods = len(kapi.exec_cli_cmd(f"kubectl get po -A -owide --field-selector spec.nodeName={node}").decode('utf-8').split('\n'))
    # Decreasing it be further 10 so that other resources in test_connectivity_reboot are created
    available_pods = max_pods - already_running_pods - 10

    resources = {ns : {}}
    manifest_path = '{}/sample-deployment.yaml'.format(DATA_DIR)
    with open(manifest_path, 'r') as file:
        manifests = yaml.safe_load_all(file)
        manifests = list(manifests)

    for manifest in manifests:
        kind = manifest.get('kind', '')

        if kind == 'Namespace':
            manifest['metadata']['name'] = ns
            lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
            resources[ns]['namespace'] = lib.create_resource(manifest['metadata']['name'], base_fixture)

        elif kind == 'Deployment':
            manifest['metadata']['namespace'] = ns
            manifest['spec']['replicas'] = available_pods
            manifest['spec']['template']['spec']['nodeName'] = node

            labels = manifest['metadata']['labels']

            lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
            resources[ns]['deployment'] = lib.create_resource(manifest['metadata']['name'], base_fixture, timeout=300)
            resources[ns]['deployment']['replicas'] = manifest['spec']['replicas']
            resources[ns]['deployment']['labels'] = f"{list(labels.keys())[0]}={list(labels.values())[0]}"


    manifest_path = '{}/nginx_service.yaml'.format(DATA_DIR)
    with open(manifest_path, 'r') as file:
        manifest = yaml.safe_load(file)

    manifest['metadata']['name'] = 'node-reboot'
    manifest['metadata']['namespace'] = ns
    manifest['spec']['selector'] = {'app':'httpd-tools-app-1'}
    manifest['spec']['ports'][0]['targetPort'] = 8080

    lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
    policy = lib.create_resource(manifest['metadata']['name'], base_fixture)
    resources[ns]['svc'] = policy
    svc = kapi.get_detail('service', policy['name'], policy['namespace'])
    resources[ns]['svc']['svc_ip'] = svc['spec']['clusterIP']
    resources[ns]['svc']['port'] = svc['spec']['ports'][0]['port']


    networkpolicy_manifest_path = '{}/namespace_networkpolicy.yaml'.format(DATA_DIR)
    with open(networkpolicy_manifest_path, 'r') as file:
        manifests = yaml.safe_load_all(file)
        manifests = list(manifests)

    for manifest in manifests:
        manifest['metadata']['namespace'] = ns
        lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
        resources[ns][manifest['metadata']['name']] = lib.create_resource(manifest['metadata']['name'], base_fixture)


    manifest_path = '{}/alpine_pod_ns1.yaml'.format(DATA_DIR)
    with open(manifest_path, 'r') as file:
        manifest = yaml.safe_load(file)

    manifest['metadata']['namespace'] = ns
    manifest['spec']['nodeName'] = node

    lib_helper.dump_template(manifest['metadata']['name'], str(manifest))
    pod = lib.create_resource(manifest['metadata']['name'], base_fixture)
    resources[ns]['pod'] = pod
    resources[ns]['pod']['image'] = manifest['spec']['containers'][0]['name']

    return resources

def check_client_pod_to_svc_curl(pod_info, svc_info):
    kapi = KubeAPI()
    svc = kapi.get_detail('service', svc_info['name'], svc_info['namespace'])
    assert len(svc) != 0, ("Service %s not found in namespace %s" %
                           (svc_info['name'], svc_info['namespace']))
    svc_ip = svc['spec']['clusterIP']
    svc_port = svc['spec']['ports'][0]['port']

    pod_label = ",".join(["%s=%s" % (k, v) for k, v in pod_info['labels'].items()])
    pods = kapi.get_detail('pod', namespace=pod_info['namespace'], labels=pod_label)
    assert len(pods['items']) != 0, ("No pod found with label %s in namespace %s" %
                                     (pod_label, pod_info['namespace']))
    for pod in pods['items']:
        verified = False
        pod_name = pod['metadata']['name']
        pod_ns = pod['metadata']['namespace']
        container = pod['spec']['containers'][0]['name']
        LOG.info("Verifying pod : %s - svc : %s connectivity with curl" % (pod_name, svc_info['name']))
        start_time = time.time()
        while time.time() - start_time < 300:
            try:
                kapi.kexec(pod_name,
                'curl %s:%s' % (svc_ip, svc_port),
                'sh -c',
                pod_ns,
                container=container)
                LOG.info("Pod : %s - svc : %s connectivity Verified" % (pod_name, svc_info['name']))
                verified = True
                break
            except Exception as e:
                LOG.info("Waiting for port to be ready")
            time.sleep(5)
        assert verified, "Failed to Verify Pod-SVC curl"

def check_pod_to_svc_curl(pod, svc_info):
    kapi = KubeAPI()
    svc = kapi.get_detail('service', svc_info['name'], svc_info['namespace'])
    assert len(svc) != 0, ("Service %s not found in namespace %s" %
                           (svc_info['name'], svc_info['namespace']))
    svc_ip = svc['spec']['clusterIP']
    svc_port = svc['spec']['ports'][0]['port']

    pod_name = pod['name']
    pod_details = kapi.get_detail('pod', pod_name, namespace=pod['namespace'])
    container = pod_details['spec']['containers'][0]['name']
    verified = False
    pod_ns = pod['namespace']
    LOG.info("Verifying pod : %s - svc : %s connectivity with curl" % (pod_name, svc_info['name']))
    start_time = time.time()
    while time.time() - start_time < 300:
        try:
            kapi.kexec(pod_name,
            'curl %s:%s' % (svc_ip, svc_port),
            'sh -c',
            pod_ns,
            container=container)
            LOG.info("Pod : %s - svc : %s connectivity Verified" % (pod_name, svc_info['name']))
            verified = True
            break
        except Exception as e:
            LOG.info("Waiting for port to be ready")
        time.sleep(5)
    assert verified, "Failed to Verify Pod-SVC curl"
