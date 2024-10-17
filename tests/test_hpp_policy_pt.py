import os
import yaml
import json
import pytest
import time
import re

from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from tests import lib, lib_helper
from tests.template_utils import env
from tests.server_utils import ServerUtils

SRV_UTILS = ServerUtils()
LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
RESOURCE_FILE = '%s/resources.yaml' % DATA_DIR
CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'
from tests.apic_apis import ApicApi
from tests.input.cfg import (APIC_PROVISION_FILE,
                             APIC_USERNAME,
                             APIC_PASSWORD)
import tests.input.cfg as cfg

MANIFEST_BASE = '''
---
apiVersion: v1
kind: Namespace
metadata:
  name: group-X-ns
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: httpd-tools-app-1
  name: httpd-tools-app-1
  namespace: group-X-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: httpd-tools-app-1
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: httpd-tools-app-1
    spec:
      containers:
      - image: quay.io/netbull/httpd-tools:3
        imagePullPolicy: IfNotPresent
        name: httpd-tools-app-1
        ports:
        - containerPort: 8080
          protocol: TCP
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-ingress
  namespace: group-X-ns
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: test-pt-np-ingress 
  podSelector: {}
  policyTypes:
  - Ingress
'''

def get_deploy_selector_label_from_mainfest():
    yamls = yaml.safe_load_all(MANIFEST_BASE)
    yamls = list(yamls)
    deploy = yamls[1]
    dep_label = deploy['metadata']['labels']
    LOG.info("Deployment label %s" % dep_label)
    return dep_label

def get_policy_ns_selector_label_from_mainfest():
    yamls = yaml.safe_load_all(MANIFEST_BASE)
    yamls = list(yamls)
    policy = yamls[2]
    ns_label = policy['spec']['ingress'][0]['from'][0]['namespaceSelector']['matchLabels']
    LOG.info("Policy ns selector label %s" % ns_label)
    return ns_label

# Create ns, deployment and network policies 
def create_resources_file(hpp_policy_cfg):
    resource_set = hpp_policy_cfg['RESOURCE_SET_COUNT']
    replicas = hpp_policy_cfg['REPLICAS']
    out = []
    for i in range(1, resource_set + 1):
        i = str(i)
        yamls = yaml.safe_load_all(MANIFEST_BASE)
        yamls = list(yamls) # generator to list

        ns_name = "group-" + i + "-ns"
        ns = yamls[0]
        ns['metadata']['name'] = ns_name

        deploy = yamls[1]
        deploy['metadata']['namespace'] = ns_name
        deploy['spec']['replicas'] = replicas

        policy = yamls[2]
        policy['metadata']['namespace'] = ns_name
        out.extend(yamls)
    with (open(RESOURCE_FILE,'w')) as f:
        yaml.dump_all(out, f)
    LOG.info(RESOURCE_FILE)

def get_input_for_deployment_and_ns(deploy, ns):
    replicas = 1
    default_label = {'key': 'test_pt', 'val': 'test_dp_pt'}
    deployment = {
        'name': deploy['name'],
        'selector' : deploy['selector'],
        'namespace': deploy.get('namespace', ns['name']),
        'labels': deploy.get('labels', default_label),
        'template': 'nginx_deployment.yaml',
        'kind': 'deployment',
        'replicas': replicas
    }
    namespace = {
        'name': ns['name'],
        'labels': ns.get('labels', default_label),
        'kind': 'Namespace',
        'template': 'namespace.yaml'
    }
    return deployment, namespace 


def create_test_topology(base_fixture, gen_template_name):
    dep_ns = 'test-pt-ns'
    selector = {'name': 'test-pt-dep'}
    deploy_in = {'name': 'nginx-deploy', 'namespace': dep_ns,
                 'selector' : selector, 'labels': selector }
    ns_in = {'name': dep_ns, 'labels': get_policy_ns_selector_label_from_mainfest()}
    deploy, ns = get_input_for_deployment_and_ns(deploy_in, ns_in)

    for rsc in [ns, deploy]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)

    return selector, dep_ns

def get_hpp_policy(server, ref_count):
    cmd = "curl http://127.0.0.1:8091/hpp"
    hpp_out = server.run(cmd)
    assert hpp_out is not None, ("hpp not fount")
    res = json.loads(hpp_out.stdout)
    for policy, v in res.items():
        r_count = v['ref-count']
        npkeys = v['npkeys'] # Array of Str
        hpp_obj = v['hpp-obj'] # Array of dict
        if r_count != ref_count:
            continue
        LOG.info(policy)
        LOG.info("ref-count %d" % r_count)
        for npkey in npkeys:
            LOG.info("npkey :  %s" % npkey)
        hdn = hpp_obj[0]['hostprotPol']['attributes']['dn']
        LOG.info("hdn %s" % hdn)
        return policy, hdn
    assert False, ("No matching hpp policy fount with ref_count %d" % ref_count)
    
def get_local_hpp_policy_convergence_time(server, ref_count):
    yamls = yaml.safe_load_all(MANIFEST_BASE)
    yamls = list(yamls)
    policy = yamls[2]
    np_hash = lib.create_hash_from_net_pol(policy['metadata'], policy['spec'])
    netpol_name = f"{lib.get_policy_tenant()}_np_{np_hash}"
    start_time = time.time()
    max_time = time.time() + 600 # 10 min
    cmd = "curl http://127.0.0.1:8091/hpp"
    # check if all the hostprotRemoteIPContainer objects are created
    pod_ns_re = re.compile(r'group.*ns')
    while True:
        if get_hostprotRemoteIpContanier_count(pod_ns_re) == ref_count:
            break
        if time.time() >= max_time:
            assert False,("Timeout")
        time.sleep(5)

    # check if the hpp policy is upated with the correct ref-count
    while True:
        hpp_out = server.run(cmd)
        assert hpp_out is not None, ("hpp not fount")
        res = json.loads(hpp_out.stdout)
        v = res.get(netpol_name)
        if ref_count == v['ref-count']:
            break
        if time.time() >= max_time:
            assert False,("Timeout")
        time.sleep(5)

    end_time = time.time()
    diff = end_time - start_time
    LOG.info("HPP converged in %s Sec after applying the config with hpp-direct enabled." % diff)
    return diff

def get_hostprotRemoteIp_from_apic(aci, policy_dn):
    ip_list = list()
    hostprotRemoteIp = aci.get_hpp_hostprotRemoteIp(policy_dn)
    if hostprotRemoteIp.get('imdata') and int(hostprotRemoteIp['totalCount']) != 0:
        ips = hostprotRemoteIp.get('imdata')
        for hprot in ips:
            hpa = hprot["hostprotRemoteIp"]["attributes"]
            hip = hpa.get("addr", False)
            if not hip:
                continue
            ip_list.append(hip)

    LOG.info("Remote IPs : %s" % ip_list)
    return ip_list

def get_hpp_policy_from_controller(ref_count):
    hostname = lib_helper.get_acc_controller_running_node()
    server = SRV_UTILS.get_server_object_by_name(hostname)
    policy, dn = get_hpp_policy(server, ref_count)
    return policy, dn

def get_apicapi():
    apic_provision = lib_helper.get_apic_provision_input(
        APIC_PROVISION_FILE)
    apic_host = apic_provision['aci_config']['apic_hosts'][0]
    try:
        aci = ApicApi(apic_host, APIC_USERNAME, APIC_PASSWORD)
    except Exception as ex:
        assert False, ("Apic Login Failed with Error : %s"
                       " Verify %s file" % (ex, APIC_PROVISION_FILE))
    return aci

TIMEOUT = 60
INTERVAL = 5
def get_hpp_programming_time(aci, policy_dn, pod_info):
    start_time = time.time()
    max_time = time.time() + TIMEOUT
    LOG.info("Pod Info %s" % pod_info)
    # For dual-stack need to update this
    expected_ip = pod_info[0][1]
    found = False
    while True:
        ip_list = get_hostprotRemoteIp_from_apic(aci, policy_dn)
        for ip in ip_list:
            if ip == expected_ip:
                LOG.info("Remote IP matching with expected IP %s" % ip)
                found = True
                break
            LOG.info("RemoteIP %s Expected IP %s" % (ip, expected_ip))
        if found:
            break
        if time.time() >= max_time:
            assert False,("Timeout")
        time.sleep(INTERVAL)
    end_time = time.time()
    diff = end_time - start_time
    LOG.info("Policy applied in %s Sec." % diff)
    return diff

def get_hostprotRemoteIpContanier_ips(pod_ns):
    kapi = KubeAPI()
    
    # Get the details of the custom resource
    cr_data = kapi.get_detail("hostprotremoteipcontainer", pod_ns, "aci-containers-system")
    
    # Extract the IP addresses
    ips = [item['addr'] for item in cr_data['spec']['hostprotRemoteIp']]
    return ips

def get_hostprotRemoteIpContanier_count(pod_ns_re):
    kapi = KubeAPI()
    resources = kapi.get_detail('hostprotremoteipcontainer', None, 'aci-containers-system')
    matching_items = [item for item in resources['items'] if re.search(pod_ns_re, item['metadata']['name'])]
    LOG.info("Matching hostprotremoteipcontainer items %s" % matching_items)
    return len(matching_items)

def get_local_hpp_programming_time(pod_info, pod_ns):
    start_time = time.time()
    max_time = time.time() + TIMEOUT
    LOG.info("Pod Info %s" % pod_info)
    # For dual-stack need to update this
    expected_ip = pod_info[0][1]
    found = False
    while True:
        ip_list = get_hostprotRemoteIpContanier_ips(pod_ns)
        for ip in ip_list:
            if ip == expected_ip:
                LOG.info("Remote IP matching with expected IP %s" % ip)
                found = True
                break
            LOG.info("RemoteIP %s Expected IP %s" % (ip, expected_ip))
        if found:
            break
        if time.time() >= max_time:
            assert False,("Timeout")
        time.sleep(INTERVAL)
    end_time = time.time()
    diff = end_time - start_time
    LOG.info("Policy applied in %s Sec." % diff)
    return diff

def check_for_resources_ready(hpp_policy_cfg):
    resource_set = hpp_policy_cfg['RESOURCE_SET_COUNT']
    replicas = hpp_policy_cfg['REPLICAS']
    selectors = get_deploy_selector_label_from_mainfest()
    for i in range(1, resource_set + 1):
        lib.wait_for_pod_running(selectors, replicas, namespace="group-" + str(i) + "-ns")

def check_for_resources_deleted(hpp_policy_cfg):
    resource_set = hpp_policy_cfg['RESOURCE_SET_COUNT']
    selectors = get_deploy_selector_label_from_mainfest()
    for i in range(1, resource_set + 1):
        lib.wait_for_resources_deleted(selectors, 'pod', namespace="group-" + str(i) + "-ns")


def get_hpp_policy_config():
    hpp_policy_cfg = dict()
    DEFAULT_HPP_POLICY_CONFIG = {
            'RESOURCE_SET_COUNT' : 100,
            'REPLICAS' : 2
    }
    
    policy_cfg = getattr(cfg, 'HPP_POLICY_CONFIG', DEFAULT_HPP_POLICY_CONFIG)
    resource_set = policy_cfg.get('RESOURCE_SET_COUNT', 100)
    replicas =  policy_cfg.get('REPLICAS', lib.get_worker_node_count())
    hpp_policy_cfg['RESOURCE_SET_COUNT'] = resource_set
    hpp_policy_cfg['REPLICAS'] = replicas
    LOG.info("Testing with HPP_POLICY_CFG %s" % hpp_policy_cfg)
    return hpp_policy_cfg


@pytest.mark.skipif(lib.is_hpp_direct_enabled() == True, reason='Local HPP is enabled')
@pytest.mark.usefixtures("clean_gen_templates")
def test_hpp_policy_pt(base_fixture, gen_template_name):
    hpp_policy_cfg = get_hpp_policy_config()
    aci = get_apicapi()
    dep_selector, dep_ns = create_test_topology(base_fixture, gen_template_name)
    # Preserve hpp optimization current value
    controller_value, hostagent_value = lib.get_hpp_optimization_controller_and_hostagent_current_value(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE)
    kapi = KubeAPI()
    try:
        # Create Resource file
        create_resources_file(hpp_policy_cfg)
        try:
            # Create Resouces 
            kapi.exec_cli_cmd("kubectl create -f %s" %  RESOURCE_FILE)
            check_for_resources_ready(hpp_policy_cfg)
        except Exception as e:
            LOG.error("Creation of %s failed. %s" % (RESOURCE_FILE, e))

        # Enable hpp optimization
        lib.update_hpp_optimization(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True, True)
        policy, policy_dn = get_hpp_policy_from_controller(hpp_policy_cfg['RESOURCE_SET_COUNT'])

        # 3) Restart dep pod 
        lib.restart_pods(dep_selector, dep_ns)
        pod_info = lib_helper.get_pods_by_labels(dep_selector, dep_ns)
        # Calculate Time
        get_hpp_programming_time(aci, policy_dn, pod_info)
    finally:
        # Delete Resouces
        try:
            LOG.info("Deleting resource %s" % RESOURCE_FILE)
            kapi.exec_cli_cmd(
                "kubectl delete -f %s" %  RESOURCE_FILE)
        except Exception as e:
            LOG.error("Deletion of %s failed. %s" % (RESOURCE_FILE, e))
        # Update hpp optimization original value
        lib.update_hpp_optimization(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE,
                controller_value, hostagent_value)


@pytest.mark.usefixtures("clean_gen_templates")
def test_local_hpp_policy_pt(base_fixture, gen_template_name):
    hpp_policy_cfg = get_hpp_policy_config()
    aci = get_apicapi()
    dep_selector, dep_ns = create_test_topology(base_fixture, gen_template_name)
    # Preserve local hpp current value
    controller_value, hostagent_value = lib.get_enable_hpp_direct_controller_and_hostagent_current_value(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE)
    kapi = KubeAPI()

    try:
        lib.update_hpp_direct(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False, False)

        create_resources_file(hpp_policy_cfg)
        try:
            kapi.exec_cli_cmd("kubectl create -f %s" %  RESOURCE_FILE)
            check_for_resources_ready(hpp_policy_cfg)
        except Exception as e:
            LOG.error("Creation of %s failed. %s" % (RESOURCE_FILE, e))

        # Get the total MO count with hpp direct disabled
        hpp_mo_count_hpp_direct_disabled = aci.get_total_mo_count(lib.get_policy_tenant())
        LOG.info("MO count with hpp direct disabled %d" % hpp_mo_count_hpp_direct_disabled)

        try:
            LOG.info("Deleting resource %s" % RESOURCE_FILE)
            kapi.exec_cli_cmd(
                "kubectl delete -f %s" %  RESOURCE_FILE)
            check_for_resources_deleted(hpp_policy_cfg)
        except Exception as e:
            LOG.error("Deletion of %s failed. %s" % (RESOURCE_FILE, e))

        # Enable hpp direct
        lib.update_hpp_direct(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True, True)

        try:
            kapi.exec_cli_cmd("kubectl create -f %s" %  RESOURCE_FILE)
            check_for_resources_ready(hpp_policy_cfg)
        except Exception as e:
            LOG.error("Creation of %s failed. %s" % (RESOURCE_FILE, e))
            
        hostname = lib_helper.get_acc_controller_running_node()
        server = SRV_UTILS.get_server_object_by_name(hostname)
        # Wait for hpp policy to converge
        get_local_hpp_policy_convergence_time(server, hpp_policy_cfg['RESOURCE_SET_COUNT'])

        # Get the total MO count with hpp direct enabled
        hpp_mo_count_hpp_direct_enabled = aci.get_total_mo_count(lib.get_policy_tenant())
        LOG.info("MO count with hpp direct enabled %d" % hpp_mo_count_hpp_direct_enabled)
        
        # Restart dep pod 
        lib.restart_pods(dep_selector, dep_ns)
        pod_info = lib_helper.get_pods_by_labels(dep_selector, dep_ns)

        # programming time in case of hpp direct
        get_local_hpp_programming_time(pod_info, dep_ns)

        assert hpp_mo_count_hpp_direct_enabled < hpp_mo_count_hpp_direct_disabled, ("\
            MO count with hpp direct enabled %d is not less than MO count with hpp direct \
                disabled %d" % (hpp_mo_count_hpp_direct_enabled, hpp_mo_count_hpp_direct_disabled))

    finally:
        # Delete Resouces
        try:
            LOG.info("Deleting resource %s" % RESOURCE_FILE)
            kapi.exec_cli_cmd(
                "kubectl delete -f %s" %  RESOURCE_FILE)
            check_for_resources_deleted(hpp_policy_cfg)
        except Exception as e:
            LOG.error("Deletion of %s failed. %s" % (RESOURCE_FILE, e))
        # Update hpp direct original value
        lib.update_hpp_direct(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE,
                controller_value, hostagent_value)
