from subprocess import TimeoutExpired

import os
import pytest
import json
from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from tests import lib, lib_helper
from tests.test_chained_mode import check_chained_mode
from tests.template_utils import env
import yaml

LOG = logger.get_logger(__name__)
BB_TEMPLATE = env.get_template('busybox.yaml')
CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'

@pytest.fixture(scope="session", autouse=True)
def update_hpp_optimization(request):
    hpp_opt = request.config.getoption("--hpp_optimization")
    if hpp_opt == "true":
        LOG.info("Network policies tests will be running with hpp-optimization enabled")
        lib.update_hpp_optimization_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
        lib.update_hpp_optimization_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
    else:
        LOG.info("Network policies tests will be running with hpp-optimization disabled")
        lib.update_hpp_optimization_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)
        lib.update_hpp_optimization_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)

    request.addfinalizer(set_default_hpp_optimization)


def set_default_hpp_optimization():
    LOG.info("Setting default hpp-optimization value :  False")
    lib.update_hpp_optimization_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)
    lib.update_hpp_optimization_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)


@pytest.fixture(scope="session", autouse=True)
def update_hpp_direct(request):
    controller_value, hostagent_value = lib.get_enable_hpp_direct_controller_and_hostagent_current_value(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE)
    hpp_direct = request.config.getoption("--hpp_direct")
    if hpp_direct == "true":
        LOG.info("Network policies tests will be running with enable-hpp-direct enabled")
        lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
        lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, True)
    else:
        LOG.info("Network policies tests will be running with enable-hpp-direct disabled")
        lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)
        lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, False)

    request.addfinalizer(lambda: set_default_hpp_direct(controller_value, hostagent_value))


def set_default_hpp_direct(controller_value, hostagent_value):
    LOG.info("Setting default enable-hpp-direct value :  False")
    lib.update_enable_hpp_direct_controller(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, controller_value)
    lib.update_enable_hpp_direct_hostagent(CONFIGMAP_NAME, CONFIGMAP_NAMESPACE, hostagent_value)


def get_input(name, generate_name=None, labels=None, namespace=None):
    arguments = locals()
    return {k: arguments[k] for k in list(arguments.keys()) if arguments[k]
            is not None}


@pytest.mark.smoke
def test_ingress_deny_policy_on_service(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tidpos'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(name='tidpos', namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    test_pod = _create_pod(
        base_fixture,
        get_input('tidpos-traffic-tester', labels={'test': 'tidpos'}, namespace=ns))
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tidpos', ingress=True, namespace=ns)
    lib.create_resource(policy_manifest, base_fixture)
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)


@pytest.mark.smoke
def test_egress_deny_policy_on_service(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tedpos'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(name='tedpos', namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    test_pod = _create_pod(
        base_fixture,
        get_input('tedpos-traffic-tester', labels={'test': 'tedpos'}, namespace=ns))
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tedpos', egress=True, namespace=ns)
    lib.create_resource(policy_manifest, base_fixture)
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)

def test_ingress_allow_named_port(base_fixture, gen_template_name):
    PORT_NAME = 'allow-port'

    #Creating namespace
    ns = 'tianp'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    # Creating traffic testing pod
    test_pod = _create_pod(
        base_fixture,
        get_input('tianp-traffic-tester', labels={'test': 'tianp'}, namespace=ns))

    # Creating the Deployment and svc with named container port
    allow_deployment, allow_svc = _get_input_for_svc_and_deployment(
        name='tianp-allow', namespace=ns, port_name=PORT_NAME)
    allow_service = _deploy_svc(
        base_fixture, allow_deployment,
        gen_template_name, allow_svc, namespace=ns)

    # Network policy to restrict ingress traffic
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tianp', ingress=True,
        target_selector={
            "matchLabels": {
                "app": "nginx"
            }
        },
        ingress_rules=[{"ports": [{
            "port": PORT_NAME
            }]}],
        namespace=ns)
    lib.create_resource(policy_manifest, base_fixture)

    # Traffic expected to pass
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(allow_service['spec']['clusterIP'],
                  allow_service['spec']['ports'][0]['port'])],
        namespace=ns)

@pytest.mark.skipif(check_chained_mode() is True, reason="Not applicable for chained mode")
def test_ingress_deny_named_port(base_fixture, gen_template_name):
    PORT_NAME = 'allow-port'

    #Creating namespace
    ns = 'tidnp'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    # Creating traffic testing pod
    test_pod = _create_pod(
        base_fixture,
        get_input('tidnp-traffic-tester', labels={'test': 'tidnp'}, namespace=ns))

    # Create named port with 80
    DATA_DIR = os.path.abspath('tests/test_data')

    named_port_path = '{}/named_port.yaml'.format(DATA_DIR)
    with open(named_port_path, 'r') as file:
        named_port = yaml.safe_load(file)

    named_port['metadata']['namespace'] = ns
    lib_helper.dump_template(named_port['metadata']['name'], str(named_port))
    lib.create_resource(named_port['metadata']['name'], base_fixture)

    # Creating deployment and svc using container port 8080
    deny_deployment, deny_svc = _get_input_for_svc_and_deployment(
        name='tidnp-deny', namespace=ns)
    deny_service = _deploy_svc(
        base_fixture, deny_deployment,
        gen_template_name, deny_svc, namespace=ns)

    # Network policy to restrict ingress traffic
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tidnp', ingress=True,
        target_selector={
            "matchLabels": {
                "app": "nginx"
            }
        },
        ingress_rules=[{"ports": [{
            "port": PORT_NAME
            }]}],
        namespace=ns)
    lib.create_resource(policy_manifest, base_fixture)


    # Traffic expected to fail, as network policy allows
    # only named container port 80
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(deny_service['spec']['clusterIP'],
                    deny_service['spec']['ports'][0]['port'])],
            namespace=ns)


def test_egress_allow_named_port(base_fixture, gen_template_name):
    PORT_NAME = 'allow-port'

    #Creating namespace
    ns = 'teanp'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    # Creating traffic testing pod
    test_pod = _create_pod(
        base_fixture,
        get_input('teanp-traffic-tester', labels={'test': 'teanp'}, namespace=ns))

    # Creating the Deployment and svc with named container port 8080
    allow_deployment, allow_svc = _get_input_for_svc_and_deployment(
        name='teanp-allow', port_name=PORT_NAME, namespace=ns)
    allow_service = _deploy_svc(
        base_fixture, allow_deployment,
        gen_template_name, allow_svc, namespace=ns)

    # Selecting traffic testing pod for egress_named_port rule
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'teanp', egress=True,
        target_selector={
                "matchLabels": {
                    "test": "teanp"
                }
        },
        egress_rules=[{"ports": [{
            "port": PORT_NAME
            }]}],
        namespace=ns)
    lib.create_resource(policy_manifest, base_fixture)

    # Traffic expected to pass
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(allow_service['spec']['clusterIP'],
                  allow_service['spec']['ports'][0]['port'])],
        namespace=ns)


@pytest.mark.skip(reason="needs discussion")
def test_egress_deny_named_port(base_fixture, gen_template_name):
    DATA_DIR = os.path.abspath('tests/test_data')
    PORT_NAME = 'allow-port'

    # Create pod to verify traffic
    test_pod = _create_pod(
        base_fixture,
        get_input('tednp-traffic-tester', labels={'test': 'tednp'}))


    # Creating named port with port 80
    lib.create_resource('{}/named_port.yaml'.format(
        DATA_DIR), base_fixture)

    # Creating deployment with port 8080
    deny_deployment, deny_svc = _get_input_for_svc_and_deployment(
        name='tednp-deny')
    deny_service = _deploy_svc(
        base_fixture, deny_deployment,
        gen_template_name, deny_svc)

    # Selecting traffic testing pod for egress_named_port rule
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tednp', egress=True,
        target_selector={
                "matchLabels": {
                    "test": "tednp"
                }
        },
        egress_rules=[{"ports": [{
            "port": PORT_NAME
            }]}])
    lib.create_resource(policy_manifest, base_fixture)


    # Traffic expected to fail, as network policy allows
    # only named container port 80
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(deny_service['spec']['clusterIP'],
                      deny_service['spec']['ports'][0]['port'])])

def test_ingress_deny_for_blacklist_pods(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tidfbp'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(name='tidfbp', namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    test_pod = _create_pod(
        base_fixture,
        get_input('tidfbp-traffic-tester', labels={'test': 'tidfbp'}, namespace=ns))
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tidfbp', ingress=True,
        ingress_rules=[{"from": [{
            "podSelector": {
                "matchLabels": {
                    "role": "frontend"
                }
            }
        }]}],
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)


def test_limit_taffic_to_an_application(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tlttap'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='tlttap', selector={'app': 'bookstore', 'role': 'api'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet', 'tlttap', ingress=True,
        ingress_rules=[
            {"from": [{
                "podSelector": {
                    "matchLabels": {
                        "app": "bookstore"
                        }}}]
             }
        ],
        target_selector={
            "matchLabels": {
                "app": "bookstore",
                "role": "api"
            }},
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    pod_without_matching_label = _create_pod(
        base_fixture, get_input('tlttap-pod1', namespace=ns))
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            pod_without_matching_label['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)
    pod_with_matching_label = _create_pod(
        base_fixture,
        get_input('tlttap-pod2',
                  labels={'app': 'bookstore', 'role': 'frontend'}, namespace=ns))
    lib.check_nw_connection_from_pod(
        pod_with_matching_label['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)


def test_deny_traffic_from_other_namespace(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tdtfon'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    ns_manifest = lib_helper.get_ns_manifest('namespace.jsonnet', 'secondary')
    lib.create_resource(ns_manifest, base_fixture)
    deployment, svc = _get_input_for_svc_and_deployment(
            name='tdtfon', namespace='secondary', non_root=True)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc,
                          namespace='secondary')
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'tdtfon',
        namespace="secondary",
        ingress=True,
        ingress_rules=[
            {"from": [{
                "podSelector": {}
                }]
             }
        ],
        target_selector={
            "matchLabels": {}
        }
    )
    lib.create_resource(policy_manifest, base_fixture)
    default_ns_pod = _create_pod(
        base_fixture, get_input('default-ns-pod', namespace=ns))
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            default_ns_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)
    secondary_ns_pod = _create_pod(
        base_fixture, get_input('secondary-ns-pod', namespace='secondary'))
    lib.check_nw_connection_from_pod(
        secondary_ns_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace='secondary')


def test_allow_all_traffic_from_a_namespace_after_pod_delete(base_fixture, gen_template_name):
    kapi = KubeAPI()
    #Creating namespace
    ns = 'taatfan'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='taatfan', selector={'app': 'web'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    dev_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'dev', labels={'purpose': 'testing'})
    lib.create_resource(dev_ns_manifest, base_fixture)
    prod_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'prod', labels={'purpose': 'production'})
    lib.create_resource(prod_ns_manifest, base_fixture)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'taatfan',
        ingress=True,
        ingress_rules=[
            {"from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "purpose": "production"
                    }
                }}]
             }
        ],
        target_selector={
            "matchLabels": {
                "app": "web"
            }
        },
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    dev_ns_pod = _create_pod(
        base_fixture, get_input('dev-ns-pod', namespace='dev'))
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            dev_ns_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace='dev')
    prod_ns_pod = _create_pod(
        base_fixture, get_input('prod-ns-pod', namespace='prod'))
    lib.check_nw_connection_from_pod(
        prod_ns_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace='prod')

    _, labels, _, _ = lib.get_deployment_details(name=deployment['name'], namespace=ns)
    kwargs = {'labels': ','.join(labels)}
    pods = kapi.get_detail('pod', namespace=ns, **kwargs)
    LOG.info("Deleting pod with labels %s"% (labels))
    for pod in pods['items']:
        kapi.delete_object('pod', pod['metadata']['name'], namespace=ns)
    replicas = lib_helper.get_cluster_node_count()
    LOG.info("Waiting for pods to come up...")
    lib.check_available_deployment_replicas(deployment['name'], deployment['namespace'], replicas)
    LOG.info("Checking connectivity after delete...")
    lib.check_nw_connection_from_pod(
        prod_ns_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace='prod')


def test_allow_all_traffic_from_a_namespace(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'taatfan'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='taatfan', selector={'app': 'web'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    dev_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'dev', labels={'purpose': 'testing'})
    lib.create_resource(dev_ns_manifest, base_fixture)
    prod_ns_manifest = lib_helper.get_ns_manifest(
        'namespace.jsonnet', 'prod', labels={'purpose': 'production'})
    lib.create_resource(prod_ns_manifest, base_fixture)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'taatfan',
        ingress=True,
        ingress_rules=[
            {"from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "purpose": "production"
                    }
                }}]
             }
        ],
        target_selector={
            "matchLabels": {
                "app": "web"
            }
        },
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    dev_ns_pod = _create_pod(
        base_fixture, get_input('dev-ns-pod', namespace='dev'))
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            dev_ns_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace='dev')
    prod_ns_pod = _create_pod(
        base_fixture, get_input('prod-ns-pod', namespace='prod'))
    lib.check_nw_connection_from_pod(
        prod_ns_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace='prod')


def test_validate_traffic_to_a_port(base_fixture, gen_template_name):
    #Creating namespace
    ns = 'tvttap'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='tvttap', selector={'app': 'apiserver'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'tvttap',
        ingress=True,
        ingress_rules=[
            {
                "ports": [{"port": 80}],
                "from": [
                    {"podSelector": {
                        "matchLabels": {
                            "role": "monitoring"
                        }}}
                ]
            }
        ],
        target_selector={
            "matchLabels": {
                "app": "apiserver"
            }
        },
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    pol_label, pol_manifest_dir = base_fixture['delete_info'][-1]
    test_pod = _create_bb_pod(
        base_fixture, gen_template_name,
        get_input('test-port-validate-trafiic', namespace=ns), BB_TEMPLATE)
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            test_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])],
            namespace=ns)
    kapi = KubeAPI()
    kapi.delete_by_label(pol_label, pol_manifest_dir)
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)


def test_allow_traffic_from_app_using_multiple_selector(base_fixture,
                                                        gen_template_name):
    #Creating namespace
    ns = 'tatfaums'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='tatfaums', selector={'app': 'bookstore', 'role': 'db'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'tatfaums',
        ingress=True,
        ingress_rules=[
            {
                "from": [
                    {
                        "podSelector": {
                            "matchLabels": {
                                "app": "bookstore",
                                "role": "search"
                            }
                        }
                    },
                    {
                        "podSelector": {
                            "matchLabels": {
                                "app": "bookstore",
                                "role": "api"
                            }
                        }
                    },
                    {
                        "podSelector": {
                            "matchLabels": {
                                "app": "inventory",
                                "role": "web"
                            }
                        }
                    }
                ]
            }
        ],
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    test_pod = _create_pod(
        base_fixture,
        get_input('test-mult-sel', labels={'app': 'inventory', 'role': 'web'}, namespace=ns))
    lib.check_nw_connection_from_pod(
        test_pod['name'], src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=ns)
    unallowed_pod = _create_pod(
        base_fixture, get_input('unallowed-pod-mult-sel', namespace=ns))
    with pytest.raises(TimeoutExpired):
        lib.check_no_nw_connection_from_pod(
            unallowed_pod['name'], src_ip=None,
            targets=[(service['spec']['clusterIP'],
                      service['spec']['ports'][0]['port'])], namespace=ns)


def test_allow_traffic_from_some_pods_in_another_namespace(
        base_fixture, gen_template_name):

    #Creating namespace
    ns = 'tatfaums'
    ns_input = lib.get_input_for_namespace(ns)
    lib.create_resource_from_template(ns_input, base_fixture)

    deployment, svc = _get_input_for_svc_and_deployment(
        name='tatfaums', selector={'app': 'web'}, namespace=ns)
    service = _deploy_svc(base_fixture, deployment, gen_template_name, svc, namespace=ns)
    ns_manifest = lib_helper.get_ns_manifest('namespace.jsonnet', 'other',
                                             labels={'team': 'operations'})
    lib.create_resource(ns_manifest, base_fixture)
    policy_manifest = lib_helper.get_nw_policy_manifest(
        'nw_policy.jsonnet',
        'tatfspian',
        ingress=True,
        ingress_rules=[
            {
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "team": "operations"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {
                                "type": "monitoring"
                            }
                        }
                    }
                ]
            }
        ],
        target_selector={
            "matchLabels": {
                "app": "web"
            }
        },
        namespace=ns
    )
    lib.create_resource(policy_manifest, base_fixture)
    test_pod = _create_pod(
        base_fixture, get_input('test-pod-1', namespace=ns))
    test_pod_with_label = _create_pod(
        base_fixture, get_input('test-pod-with-label',
                                labels={'type': 'monitoring'}, namespace=ns))
    test_pod_other_ns = _create_pod(
        base_fixture, get_input('test-pod-other-ns', namespace='other'))
    for _pod in [test_pod, test_pod_with_label, test_pod_other_ns]:
        with pytest.raises(TimeoutExpired):
            lib.check_no_nw_connection_from_pod(
                _pod['name'], src_ip=None,
                targets=[(service['spec']['clusterIP'],
                          service['spec']['ports'][0]['port'])],
                namespace=_pod['namespace']
            )
    test_pod_with_label_in_other_ns = _create_pod(
        base_fixture, get_input('test-pod-with-label-other-ns',
                                namespace='other',
                                labels={'type': 'monitoring'}))
    lib.check_nw_connection_from_pod(
        test_pod_with_label_in_other_ns['name'],
        src_ip=None,
        targets=[(service['spec']['clusterIP'],
                  service['spec']['ports'][0]['port'])],
        namespace=_pod['namespace'])


def _deploy_svc(base_fixture, deployment, gen_template_name, svc,
                namespace='default'):
    for rsc in [deployment, svc]:
        template = env.get_template(rsc['template'])
        rend_temp = template.render(input=rsc)
        temp_name = gen_template_name(rsc['name'])
        lib_helper.dump_template(temp_name, rend_temp)
        lib.create_resource(temp_name, base_fixture)
    return lib.get_detail('service', svc['name'], namespace=namespace)


def _create_bb_pod(base_fixture, gen_template_name, pod_input, pod_template):
    rend_temp = pod_template.render(pod=pod_input)
    temp_name = gen_template_name(pod_input['name'])
    lib_helper.dump_template(temp_name, rend_temp)
    return lib.create_resource(temp_name, base_fixture)


def _create_pod(base_fixture, pod_input):
    pod_manifest = lib_helper.get_pod_manifest(
        'alp.jsonnet', pod_input['name'], pod_input.get('namespace'),
        pod_input.get('labels'))
    return lib.create_resource(pod_manifest, base_fixture)


def _get_input_for_svc_and_deployment(name, namespace='default',
                                      selector=None, non_root=False,
                                      tport=8080, port_name=None):
    replicas = lib_helper.get_cluster_node_count()
    deployment = {
        'name': '%s-nginx-deploy' % name,
        'template': 'nginx_deployment.yaml',
        'kind': 'deployment',
        'replicas': replicas,
        'namespace': namespace
    }
    svc = {
        'name': '%s-nginx-svc' % name,
        'template': 'nginx_service.yaml',
        'kind': 'service',
        'namespace': namespace,
        'target_port': tport
    }
    if port_name:
        deployment['port_name'] = svc['port_name'] = port_name
    if selector:
        deployment['selector'] = svc['selector'] = selector
    if non_root:
        deployment['template'] = 'nginx_non_root_deployment.yaml'
    return deployment, svc


def ping_from_pod(pod_info, target_ip, target='pod'):
    lib_helper.check_ping_from_pod(
        pod_info['name'], pod_info['namespace'], target_ip, target=target)
