from subprocess import TimeoutExpired
import pytest

from acc_pyutils.exceptions import KctlExecutionFailed
from tests import lib_helper, lib
from acc_pyutils.utils import execute
from acc_pyutils.api import KubeAPI

DATA_DIR = 'tests/test_data'

def test_os_nw_policies(base_fixture):
        kapi = KubeAPI()
        try:
            # Creates the project using oc command
            prj_a = 'ci-sddc2375-network-policies-a'
            prj_b = 'ci-sddc2375-network-policies-b'
            lib.create_resource('{}/sddc_2375_prj_a.yaml'.format(DATA_DIR),
                base_fixture)
            lib.create_resource('{}/sddc_2375_prj_b.yaml'.format(DATA_DIR),
                base_fixture)

            # (NK): this is not working, refer this later
            # lib.create_resource('{}/sddc_2375_sa_a.yaml'.format(DATA_DIR),
            #     base_fixture)
            # lib.create_resource('{}/sddc_2375_sa_b.yaml'.format(DATA_DIR),
            #     base_fixture)
            create_sa = 'oc create serviceaccount runasanyuid -n %s'
            prj_a_sa = create_sa % prj_a
            prj_b_sa = create_sa %  prj_b
            execute(prj_a_sa.split(" "))
            execute(prj_b_sa.split(" "))

            add_scc = 'oc adm policy add-scc-to-user anyuid' \
                ' -z runasanyuid --as system:admin' \
                ' -n %s'
            prj_a_scc = add_scc % (prj_a)
            prj_b_scc = add_scc % (prj_b)
            execute(prj_a_scc.split(" "))
            execute(prj_b_scc.split(" "))

            lib.create_resource('{}/sddc_2375_dc_1.yaml'.format(DATA_DIR),
                base_fixture)
            lib.create_resource('{}/sddc_2375_dc_2.yaml'.format(DATA_DIR),
                base_fixture)

            svc_a = lib.create_resource(
                '{}/sddc_2375_svc_1.yaml'.format(DATA_DIR),
                base_fixture)
            svc_b = lib.create_resource(
                '{}/sddc_2375_svc_2.yaml'.format(DATA_DIR),
                base_fixture)

            rt_a = lib.create_resource(
                '{}/sddc_2375_route_1.yaml'.format(DATA_DIR),
                base_fixture)
            rt_b = lib.create_resource(
                '{}/sddc_2375_route_2.yaml'.format(DATA_DIR),
                base_fixture)

            lib.create_resource('{}/policyDenyAll.yaml'.format(DATA_DIR),
                base_fixture)
            lib.create_resource(
                '{}/policyAllowOpenshiftIngress.yaml'.format(DATA_DIR),
                base_fixture)
            lib.create_resource(
                '{}/policyAllowOpenshiftMonitoring.yaml'.format(DATA_DIR),
                base_fixture)
            lib.create_resource(
                '{}/policyAllowSameNamespace.yaml'.format(DATA_DIR),
                base_fixture)


            labels = 'network.openshift.io/policy-group=ingress'
            kapi.apply_label('namespace', False, None, 'default',
                             labels, name='default')


            pod_selector = {
                'app': 'httpd-tools-app-1'
            }
            pod_a_name, pod_a_ip, _ = lib_helper.get_pods_by_labels(pod_selector,
             prj_a)[0]
            pod_b_name, pod_b_ip, _ = lib_helper.get_pods_by_labels(pod_selector,
             prj_b)[0]
            # Ping from name_space_a pod to name_space_b pod
            # This is expected to pass
            lib_helper.check_ping_from_pod(
                pod_a_name,
                prj_a,
                pod_b_ip)

            # Ping from name_space_b pod to name_space_a_pod
            # This is expected to fail
            with pytest.raises(KctlExecutionFailed):
                lib_helper.check_ping_from_pod(
                    pod_b_name,
                    prj_b,
                    pod_a_ip)

            svc_a = kapi.get_detail('service', name=svc_a['name'],
             namespace=prj_a)
            svc_b = kapi.get_detail('service', name=svc_b['name'],
             namespace=prj_b)
            svc_a_ip = svc_a['spec']['clusterIP']
            svc_b_ip = svc_b['spec']['clusterIP']


            rt_a = kapi.get_detail('route', name=rt_a['name'],
             namespace=prj_a)
            rt_b = kapi.get_detail('route', name=rt_b['name'],
             namespace=prj_b)
            rt_a_url = rt_a['spec']['host']
            rt_b_url = rt_b['spec']['host']

            # Ping from name_space_a_pod to name_space_b pod, svc, route
            # This traffic is expected to pass
            for dest_ip in [pod_b_ip, svc_b_ip, rt_b_url]:
                lib.check_nw_connection_from_pod(pod_a_name,
                                                 src_ip=pod_a_ip,
                                                 targets=[(dest_ip, '80')],
                                                 namespace=prj_a)

            # Ping from name_space_b_pod to name_space_a pod, svc, route
            # This traffic is expected to fail
            for dest_ip in [pod_a_ip, svc_a_ip, rt_a_url]:
                with pytest.raises(TimeoutExpired):
                    lib.check_no_nw_connection_from_pod(pod_b_name,
                                                     src_ip=pod_b_ip,
                                                     targets=[(
                                                     dest_ip,
                                                     '80'
                                                     )], namespace=prj_b)
        finally:
            # Delete all the created resources
            try:
                delete_sa = 'oc delete serviceaccount runasanyuid -n %s'
                delete_sa_a = delete_sa % prj_a
                delete_sa_b = delete_sa % prj_b
                execute(delete_sa_a.split(" "))
                execute(delete_sa_b.split(" "))
                labels = 'network.openshift.io/policy-group-'
                kapi.delete_label('namespace', 'default', labels,
                    name="default")
            except Exception:
                pass
