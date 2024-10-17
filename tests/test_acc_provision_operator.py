import json
import random
import subprocess
import tabulate
import time
import threading
import yaml

from acc_pyutils import logger
from acc_pyutils.acc_cfg import get_kube_client
from acc_pyutils.api import KubeAPI
from datetime import datetime
from pprint import pformat
from tests import lib
from tests.input.cfg import (ACI_CONTAINERS_HOST_VERSION,
                             ACI_CNI_OPERATOR_VERSION,
                             REVERT_UPDATE,
                             RESOURCE_PROFILING_ENABLE)

ACI_OPERATOR_POD_LABEL = 'aci-containers-operator'
ACI_CONTAINERS_NAMESPACE = 'aci-containers-system'
ACC_PROVISION_OPERATOR_CR = 'accprovisioninput'
ACI_CONTAINERS_CONFIGMAP = 'aci-containers-config'
ACC_PROVISION_OPERATOR_CONT_NAME = 'acc-provision-operator'
ACI_CONTAINERS_OPERATOR_POD_LABEL = 'aci-containers-operator'
CR_FILE = '/tmp/acc_provision_input_cr.yaml'
LOCAL_VERSION_FP = '/tmp/versions.yaml'
LOG = logger.get_logger(__name__)
KUBE_CLIENT = get_kube_client()
KAPI = KubeAPI()
RECONCILE_PERIOD = 60
RESOURCE_PROFILING_INTERVAL = 5
# maximum waiting time to verify status of ACI Pods.
MAX_WAITING_TIME = 600
INTERVAL = 20
# maximum waiting time for log levels to get reflected in configmap
CM_UPDATE_WAITING_TIME = 80
VERSION_FP = '/opt/ansible/acc-provision/provision/acc_provision/versions.yaml'
RESOURCE_USAGE = '/tmp/mapping.json'
# List of registry tags.
REGISTRY = ['aci_cni_operator_version',
            'acc_provision_operator_version',
            'aci_containers_controller_version',
            'aci_containers_host_version',
            'aci_containers_operator_version',
            'cnideploy_version',
            'openvswitch_version',
            'opflex_agent_version']

ACI_CONTAINERS_CONFIGS = {
    'controller-config',
    'host-agent-config',
    'opflex-agent-config'
}
DEFAULT_LOG_LEVELS = {
    'controller_log_level': 'info',
    'hostagent_log_level': 'info',
    'opflexagent_log_level': 'info'
}
POSSIBLE_LOG_LEVEL_KEYS = {
    'controller_log_level',
    'hostagent_log_level',
    'opflexagent_log_level'
}
POSSIBLE_LOG_LEVEL_VALUES = {'debug', 'info', 'trace'}


def test_verify_accprovisioninput_cr():
    acc_provision_op_info = _get_acc_provision_input_manifest()
    assert acc_provision_op_info, ("Unable to get details of "
                                   "accprovisioninput CR [%s]"
                                   % ACC_PROVISION_OPERATOR_CR)


def test_verify_host_agent_image():
    """Test host agent image version update.

    Modify/Add host agent image version field of acc-provision CR.
    and confirm that all the host agent pods restart with the correct
    version. It also restore to earlier version/config after successful
    update if REVERT_UPDATE config is enable.
    """
    enable_updates = _get_update_enable_config()
    _verify_host_agent_image_version_update(enable_updates)
    _set_update_enable_config(not enable_updates)
    new_enable_updates = _get_update_enable_config()
    _verify_host_agent_image_version_update(new_enable_updates)
    _set_update_enable_config(enable_updates)


def test_upgrade_cni_version():
    """Test CNI Version Upgrade.

    Update aci_cni_operator_version image field of acc-provision CR i.e
    (accprovisioninput) with image version provided in config file,
    and verify if all the CNI pods i.e (controller, hostagent, ovs etc) are
    upgraded with the correct version. for non disruptive upgrades
    i.e (enable_updates is set as false) all the CNI pods are expected
    to remain in the same state. It also restore to earlier version/config
    after successful upgrade if REVERT_UPDATE config is enable.
    """
    # get existing enable_updates config value.
    enable_updates = _get_update_enable_config()
    _verify_cni_upgrade(enable_updates)
    # change the enable_updates config value.
    _set_update_enable_config(not enable_updates)
    new_enable_updates = _get_update_enable_config()
    _verify_cni_upgrade(new_enable_updates)
    # revert back enable_updates config value.
    _set_update_enable_config(enable_updates)


def test_display_resource_usage_of_acc_provision_operator():
    """Display resource utilization of ACI containers operator pod

    This test display resource utilization i.e (CPU/Memory)
    of POD i.e aci containers operator, It will collect and
    display data for interval of reconcile period i.e (60 seconds).
    """
    stop_threads, resource_utilization_data, thread1 = False, list(), None
    LOG.info("Display logging level")
    _display_logging_level()
    thread1 = threading.Thread(target=_log_resource_utilization, args=(
        lambda: stop_threads, resource_utilization_data,))
    thread1.daemon = True
    thread1.start()
    LOG.info("Waiting up to reconcile period of %s second to "
             "collect resource utilization data of aci "
             "containers operator pod." % RECONCILE_PERIOD)
    time.sleep(RECONCILE_PERIOD)
    stop_threads = True
    thread1.join()
    _display_data(resource_utilization_data)


def test_update_log_levels(base_fixture):
    '''
        Update log levels while 'enable_updates' flag
        in cr file is 'set' as well as when 'not set'
    '''
    enable_updates = _get_update_enable_config()
    _update_log_levels(enable_updates)

    _set_update_enable_config(not enable_updates)
    new_enable_updates = _get_update_enable_config()
    _update_log_levels(new_enable_updates)

    # revert back to original state
    _set_update_enable_config(enable_updates)


def test_delete_log_levels():
    '''
        Delete log levels while 'enable_updates' flag
        in cr file is 'set' as well as when 'not set'
    '''
    enable_updates = _get_update_enable_config()
    LOG.info(enable_updates)
    _delete_log_levels(enable_updates)

    _set_update_enable_config(not enable_updates)
    new_enable_updates = _get_update_enable_config()
    _delete_log_levels(new_enable_updates)

    # revert back to original state
    _set_update_enable_config(enable_updates)


def _update_log_levels(enable_updates):
    '''
        Change log levels in "accprovisioninput" cr file and
        check if the change is reflected into "aci-containers-config" configmap
    '''
    # Get current log levels...
    # (while 'enable_updates' is 'false',
    # log_levels in cr & cm can have diffrent values)
    cm_log_lvls = _get_log_levels_from_configmap()
    cr_log_lvls = _get_log_levels_from_accprovisioninput()
    # create updated log levels randomly
    log_level_new = cm_log_lvls.copy()
    for k in log_level_new:
        log_level_new[k] = random.choice(
            list(
                POSSIBLE_LOG_LEVEL_VALUES - {log_level_new[k]}
            )
        )

    # update log levels & check if the changes reflected in Configmap
    updated = _changes_reflected_in_configmap(
        _update_accprovisioninput_log_level(log_level_new)
    )

    if enable_updates is True:
        # if Update flag is set. Changes should get reflected
        assert updated
        # reverting cr back to original state, cm should reflect
        LOG.info("Revert back to original log levels...")
        assert _changes_reflected_in_configmap(
            _update_accprovisioninput_log_level(cm_log_lvls)
        )
    else:
        # When Update flag is not set. Changes shouldn't get reflected"
        assert not updated
        # reverting cr back to original state
        _update_accprovisioninput_log_level(cr_log_lvls)


def _delete_log_levels(enable_updates):
    '''
        delete the log_level entry(the entire key-value pair)
        from cr file and check that it's reverting back to
        default value in "aci-containers-config" configmap
    '''
    # getting current log levels
    cm_log_lvls = _get_log_levels_from_configmap()
    cr_log_lvls = _get_log_levels_from_accprovisioninput()

    if cm_log_lvls == DEFAULT_LOG_LEVELS:
        LOG.info("Log levels deletion must be \
            tested against non default log lvls.")
        return

    # delete all log levels & check if the changes reflected in Configmap
    deleted = _changes_reflected_in_configmap(
        _delete_log_level_in_accprovisioninput(POSSIBLE_LOG_LEVEL_KEYS)
    )

    if enable_updates is True:
        # log level changes get reflected
        assert deleted

        # back to original state & check if the changes reflected in Configmap
        LOG.info("Revert back to original log levels...")
        assert _changes_reflected_in_configmap(
            _update_accprovisioninput_log_level(cm_log_lvls)
        )
    else:
        assert not deleted
        _update_accprovisioninput_log_level(cr_log_lvls)


def _get_log_levels_from_accprovisioninput() -> dict:
    accprovisioninput = _get_acc_provision_input_manifest()
    log_levels = accprovisioninput['spec']['acc_provision_input']['logging']
    return log_levels


def _get_log_levels_from_configmap() -> dict:
    aci_containers_config = KAPI.get_detail(
        obj_type='configmap',
        name=ACI_CONTAINERS_CONFIGMAP,
        namespace=ACI_CONTAINERS_NAMESPACE
    )
    controller_config = json.loads(
        aci_containers_config['data']['controller-config']
    )
    host_agent_config = json.loads(
        aci_containers_config['data']['host-agent-config']
    )
    opflex_agent_config = json.loads(
        aci_containers_config['data']['opflex-agent-config']
    )
    log_levels = {
        'controller_log_level': controller_config['log-level'],
        'hostagent_log_level': host_agent_config['log-level'],
        'opflexagent_log_level': opflex_agent_config['log']['level']
    }
    LOG.info(f"Current log levels: {log_levels}")
    return log_levels


def _delete_log_level_in_accprovisioninput(
        rm_keys: set = POSSIBLE_LOG_LEVEL_KEYS) -> dict:
    '''
        Delete log levels in accprovision operator.\n
        \n
        parameter(s):
        rm_keys: set of log levels to be removed\n
        returns: log levels after deletion is performed
    '''
    log_levels = _get_log_levels_from_configmap()
    # new_log_levels = log_levels.copy()
    expected_log_levels = log_levels.copy()
    LOG.info(f"Log levels to be deleted: {rm_keys}")
    for k in rm_keys:
        del log_levels[k]
        expected_log_levels[k] = DEFAULT_LOG_LEVELS[k]
    accprovisioninput = _get_acc_provision_input_manifest()
    accprovisioninput['spec']['acc_provision_input']['logging'] = log_levels
    _create_and_apply_cr_manifest(accprovisioninput)
    return expected_log_levels


def _update_accprovisioninput_log_level(new_log_levels) -> dict:
    '''
    Update log levels in accprovision operator.\n
    \n
    parameter(s):
    new_log_levels: log level key-value pair(s)\n
    e.g Suppose current crd have 3 types of logging with following values,\n
        'controller_log_level': 'info',
        'hostagent_log_level': 'info',
        'opflexagent_log_level': 'trace'
    Now if you call this function with following parameter,\n
        new_log_levels = {'controller_log_level': 'debug'}\n
    it'll update controller's log level while other two will remain unchanged\n
    \n
    returns: log levels after applying update
    '''
    accprovisioninput = _get_acc_provision_input_manifest()
    log_levels = accprovisioninput['spec']['acc_provision_input']['logging']
    for k in new_log_levels:
        log_levels[k] = new_log_levels[k]
    LOG.info(f"Modified log levels: {log_levels}")
    _create_and_apply_cr_manifest(accprovisioninput)
    return log_levels


def _changes_reflected_in_configmap(log_levels) -> bool:
    '''
    returns True if changes in log level(s) are reflected in configmap
    '''
    LOG.info(f"Waiting for followig changes \
        to get reflected in Configmap: {log_levels}")
    max_time = time.time() + CM_UPDATE_WAITING_TIME
    while True:
        curr_log_levels = _get_log_levels_from_configmap()
        if curr_log_levels == log_levels:
            LOG.info("Changes in log levels are reflected in configmap.")
            return True
        if time.time() >= max_time:
            LOG.info("Timeout. Changes in log levels \
                are not getting reflected in configmap.")
            return False
        time.sleep(INTERVAL)


def _verify_host_agent_image_version_update(enable_updates_tag):
    """Verify host agent image version update."""
    stop_threads, resource_utilization_data, thread1 = False, list(), None
    upgrade_type = "Disruptive Upgrades" if enable_updates_tag \
        else "Non Disruptive upgrade"
    LOG.info("Verifying ACI containers host image "
             "version update in %s mode" % upgrade_type)
    assert ACI_CONTAINERS_HOST_VERSION, (
        "ACI containers Host version is not provided in config file")
    aci_containers_host_image = _get_aci_containers_image(
        'daemonset', 'aci-containers-host', 'aci-containers-host')
    aci_containers_host_image_tag = aci_containers_host_image.split(":")[1]
    assert ACI_CONTAINERS_HOST_VERSION != aci_containers_host_image_tag, (
            "ACI containers host agents Pods are already running with "
            "image[%s], Please provide other image version"
            % aci_containers_host_image_tag)
    acc_provision_input_manifest = _get_acc_provision_input_manifest()
    registry_images = _get_registry_images(acc_provision_input_manifest)
    orig_registry = registry_images.copy()
    pod_list = _get_pod_list_for_label('aci-containers-host',
                                       ACI_CONTAINERS_NAMESPACE)
    acc_provision_input_manifest['spec']['acc_provision_input']['registry'][
        'aci_containers_host_version'] = ACI_CONTAINERS_HOST_VERSION
    # start logging resource utilization of aci containers operator pod
    if RESOURCE_PROFILING_ENABLE:
        thread1 = threading.Thread(target=_log_resource_utilization, args=(
            lambda: stop_threads, resource_utilization_data,))
        thread1.daemon = True
        thread1.start()
    try:
        # apply new config to accprovisioninput CR
        _create_and_apply_cr_manifest(acc_provision_input_manifest)
    except Exception as er:
        LOG.info("Failed to apply to new config, Restoring "
                 "original config of accprovisioninput CR")
        _restore_registry_spec_config(orig_registry)
        assert False, ("Failed to apply new config to "
                       "accprovisioninput CR, Reason: %s" % er)

    if not enable_updates_tag:
        LOG.info("Waiting up to %s seconds of reconcile period "
                 "in non disruptive upgrade." % RECONCILE_PERIOD)
        time.sleep(RECONCILE_PERIOD)
    expected_aci_containers_host_image = ACI_CONTAINERS_HOST_VERSION if \
        enable_updates_tag else aci_containers_host_image_tag
    try:
        _verify_aci_containers_host_version(
            expected_aci_containers_host_image, pod_list, enable_updates_tag)
        LOG.info("Host Agent Image version is updated successfully "
                 "with version[%s]" % expected_aci_containers_host_image)
    except Exception as er:
        LOG.info("Failed to update host agent version, "
                 "Restoring to original accprovisioninput CR config")
        _restore_registry_spec_config(orig_registry)
        stop_threads = True
        _display_data(resource_utilization_data)
        assert False, ("Host agent image version update "
                       "is failed Reason: %s" % er)
    if RESOURCE_PROFILING_ENABLE:
        stop_threads = True
        thread1.join()
        _display_data(resource_utilization_data)
    if not REVERT_UPDATE:
        return
    pod_list = _get_pod_list_for_label('aci-containers-host',
                                       ACI_CONTAINERS_NAMESPACE)
    if enable_updates_tag:
        LOG.info("Restore Host Agent image version to "
                 "version [%s] " % aci_containers_host_image_tag)
    _restore_registry_spec_config(orig_registry)
    if not enable_updates_tag:
        LOG.info("Waiting up to %s seconds of reconcile period "
                 "in non disruptive upgrade." % RECONCILE_PERIOD)
        time.sleep(RECONCILE_PERIOD)
    LOG.info("Verifying aci-containers-host container image for daemonset "
             "aci-containers-host, Expected image version is %s"
             % aci_containers_host_image_tag)
    _verify_aci_containers_host_version(
        aci_containers_host_image_tag, pod_list, enable_updates_tag)
    if enable_updates_tag:
        LOG.info("Host Agent Image is restored to original version"
                 "successfully with Image[%s]" % aci_containers_host_image_tag)
    LOG.info("ACI Containers Host image version update in %s mode "
             "is verified successfully" % upgrade_type)


def _verify_cni_upgrade(enable_updates_tag):
    """Verify CNI Version Upgrade."""
    stop_threads, resource_utilization_data, thread1 = False, list(), None
    upgrade_type = "Disruptive Upgrades" if enable_updates_tag \
        else "Non Disruptive upgrade"
    LOG.info("Verifying CNI Upgrade in %s mode" % upgrade_type)
    assert ACI_CNI_OPERATOR_VERSION, (
        "ACC Provision Operator image is not provided in config")
    # get acc-provision-operator image name
    acc_provision_op_image_tag = _get_acc_provision_op_image()
    assert ACI_CNI_OPERATOR_VERSION != acc_provision_op_image_tag, (
            "ACC provision operator container is already running "
            "with image[%s], Please provide other image version"
            % acc_provision_op_image_tag)
    LOG.info("Upgrading CNI version from [%s] to [%s]" % (
        acc_provision_op_image_tag, ACI_CNI_OPERATOR_VERSION))
    aci_op_pod, aci_ovs_pod, aci_host_pod, aci_controller_pod = \
        _get_aci_pod_list(ACI_CONTAINERS_NAMESPACE)
    acc_provision_input_manifest = _get_acc_provision_input_manifest()
    registry_images = _get_registry_images(acc_provision_input_manifest)
    orig_registry = registry_images.copy()
    acc_provision_input_manifest['spec']['acc_provision_input']['registry'][
        'aci_cni_operator_version'] = ACI_CNI_OPERATOR_VERSION
    _remove_registry_field_if_required(acc_provision_input_manifest)
    # start resource profiling of aci containers operator pod
    if RESOURCE_PROFILING_ENABLE:
        thread1 = threading.Thread(target=_log_resource_utilization, args=(
            lambda: stop_threads, resource_utilization_data,))
        thread1.daemon = True
        thread1.start()
    staring_time = time.time()
    try:
        _create_and_apply_cr_manifest(acc_provision_input_manifest)
    except Exception as er:
        LOG.info("Failed to apply to new config, Restoring "
                 "original config of accprovisioninput CR")
        _restore_registry_spec_config(orig_registry)
        assert False, ("Failed to apply new config to "
                       "accprovisioninput CR, Reason: %s" % er)
    if not enable_updates_tag:
        LOG.info("Waiting up to %s seconds of reconcile period "
                 "in non disruptive upgrade mode." % RECONCILE_PERIOD)
        time.sleep(RECONCILE_PERIOD)

    expected_aci_cni_operator_version = ACI_CNI_OPERATOR_VERSION if \
        enable_updates_tag else acc_provision_op_image_tag
    try:
        _verify_aci_ds_deploy_images(expected_aci_cni_operator_version,
                                     aci_op_pod, aci_ovs_pod,
                                     aci_host_pod, aci_controller_pod,
                                     enable_updates_tag)
    except Exception as er:
        LOG.error("Failed to upgrade CNI version, Restoring"
                  "to original accprovisioninput CR config")
        stop_threads = True
        _restore_registry_spec_config(orig_registry)
        _display_data(resource_utilization_data)
        assert False, ("CNI upgrade is failed , Reason: %s" % er)
    finish_time = time.time()
    if enable_updates_tag:
        LOG.info("CNI version is upgraded successfully from [%s] to [%s]"
                 % (acc_provision_op_image_tag, ACI_CNI_OPERATOR_VERSION))
        LOG.info("CNI UPGRADE took %d seconds" % (finish_time - staring_time))
    if RESOURCE_PROFILING_ENABLE:
        stop_threads = True
        thread1.join()
        _display_data(resource_utilization_data)
    if not REVERT_UPDATE:
        return

    # get updated aci cni pod list
    aci_op_pod, aci_ovs_pod, aci_host_pod, aci_controller_pod = \
        _get_aci_pod_list(ACI_CONTAINERS_NAMESPACE)
    if enable_updates_tag:
        LOG.info("Restore CNI version to original version[%s] "
                 "after successful CNI upgrade" % acc_provision_op_image_tag)
    _restore_registry_spec_config(orig_registry)
    if not enable_updates_tag:
        LOG.info("Waiting up to %s seconds of reconcile period "
                 "in non disruptive upgrade." % RECONCILE_PERIOD)
        time.sleep(RECONCILE_PERIOD)
    _verify_aci_ds_deploy_images(acc_provision_op_image_tag,
                                 aci_op_pod, aci_ovs_pod,
                                 aci_host_pod, aci_controller_pod,
                                 enable_updates_tag)
    if enable_updates_tag:
        LOG.info("CNI Version is restored to original version [%s]"
                 % acc_provision_op_image_tag)
    LOG.info("CNI upgrade in %s mode "
             "is Verified successfully" % upgrade_type)


def _verify_aci_containers_host_version(aci_containers_host_image,
                                        pod_list, enable_updates_tag):
    LOG.info("Verifying aci-containers-host container image for daemonset "
             "aci-containers-host, Expected image version is %s"
             % aci_containers_host_image)
    lib.check_aci_containers_image('daemonset',
                                   'aci-containers-host',
                                   'aci-containers-host',
                                   aci_containers_host_image,
                                   ACI_CONTAINERS_NAMESPACE)
    if enable_updates_tag:
        _check_aci_pods_status("aci-containers-host",
                               exclude_pod_list=pod_list)
    else:
        _check_aci_pods_status("aci-containers-host",
                               include_pod_list=pod_list)


def _verify_aci_ds_deploy_images(aci_cni_operator_version,
                                 aci_op_pod, aci_ovs_pod,
                                 aci_host_pod, aci_controller_pod,
                                 enable_updates_tag):
    _verify_deployment_images(aci_cni_operator_version)
    if enable_updates_tag:
        _check_aci_pods_status("aci-containers-operator",
                               exclude_pod_list=aci_op_pod)
    else:
        _check_aci_pods_status("aci-containers-operator",
                               include_pod_list=aci_op_pod)
    # NOTE: it's observed that sometimes oc exec on aci-containers-operator i.e
    # oc exec aci-containers-operator-<id> -c acc-provision-operator is failing
    # even after aci-containers-operator pod come up in running state
    # adding some delay to resolve this for now.
    time.sleep(20)
    updated_aci_containers_operator_pod = \
        _get_aci_containers_operator_pod()
    _verify_aci_containers_images(updated_aci_containers_operator_pod)
    _verify_aci_pod_status(aci_ovs_pod, aci_host_pod,
                           aci_controller_pod, enable_updates_tag)


def _display_logging_level():
    aci_containers_config = KAPI.get_detail(
        'configmap', ACI_CONTAINERS_CONFIGMAP,
        ACI_CONTAINERS_NAMESPACE)
    controller_config = json.loads(
        aci_containers_config['data']['controller-config'])
    host_agent_config = json.loads(
        aci_containers_config['data']['host-agent-config'])
    opflex_agent_config = json.loads(
        aci_containers_config['data']['opflex-agent-config'])
    controller_log_level = controller_config['log-level']
    hostagent_log_level = host_agent_config['log-level']
    opflexagent_log_level = opflex_agent_config['log']['level']
    LOG.info("Controller Log Level is %s" % controller_log_level)
    LOG.info("Host Agent Log Level is %s" % hostagent_log_level)
    LOG.info("Opflex Agent Log Level is %s" % opflexagent_log_level)


def _remove_registry_field_if_required(acc_provision_input_manifest):
    registry_list = [
        value for value in REGISTRY if value != "aci_cni_operator_version"]
    registry_keys = acc_provision_input_manifest['spec'][
        'acc_provision_input']['registry'].keys()
    for key in list(registry_keys):
        if key in registry_list:
            acc_provision_input_manifest['spec'][
                'acc_provision_input']['registry'].pop(key)
            LOG.info("Removing registry field[%s] from AccProvisionInput "
                     "CR " % key)


def _get_acc_provision_op_image():
    aci_container_op_dep = _get_aci_containers_image(
        'deployment', 'aci-containers-operator', 'acc-provision-operator')
    acc_provision_op_tag = aci_container_op_dep.split(":")[1]
    return acc_provision_op_tag


def _restore_registry_spec_config(registry_config):
    cr_config = _get_acc_provision_input_manifest()
    cr_config['spec']['acc_provision_input'][
        'registry'] = registry_config
    _create_and_apply_cr_manifest(cr_config)


def _get_pods_with_label(pod_label, namespace):
    pod_list = list()
    p_label = 'name={}'.format(pod_label)
    temp = {'labels': p_label}
    pod_info = KAPI.get_detail('pod', namespace=namespace, **temp)
    for pod in pod_info['items']:
        pod_name = pod['metadata']['name']
        pod_list.append(pod_name)
    return pod_list


def _get_acc_provision_version(aci_op_pod, namespace):
    cmd = '-- acc-provision --version'
    cont = {'container': 'acc-provision-operator'}
    res1 = KAPI.kexec(aci_op_pod, cmd, namespace=namespace, **cont)
    res = res1.decode().split('.')
    acc_provision_version = '%s.%s' % (res[0], res[1])
    LOG.info("acc provision version is %s" % acc_provision_version)
    return float(acc_provision_version)


def _get_version_details(aci_op_pod, acc_provision_version):
    cmd = 'kubectl cp %s/%s:%s %s -c %s' % (
        ACI_CONTAINERS_NAMESPACE, aci_op_pod, VERSION_FP,
        LOCAL_VERSION_FP, ACC_PROVISION_OPERATOR_CONT_NAME)
    lib.exec_cmd(cmd)
    with open(LOCAL_VERSION_FP, 'r') as vf:
        version_info = yaml.load(vf, Loader=yaml.SafeLoader)
    return version_info['versions'][acc_provision_version]


def _get_aci_containers_operator_pod():
    aci_op_pod = _get_pods_with_label(
        ACI_CONTAINERS_OPERATOR_POD_LABEL, ACI_CONTAINERS_NAMESPACE)
    return aci_op_pod[0]


def _get_aci_pod_list(namespace):
    aci_op_pod = _get_pod_list_for_label('aci-containers-operator',
                                         namespace)
    aci_ovs_pod = _get_pod_list_for_label('aci-containers-openvswitch',
                                          namespace)
    aci_host_pod = _get_pod_list_for_label('aci-containers-host',
                                           namespace)
    aci_controller_pod = _get_pod_list_for_label(
        'aci-containers-controller', namespace)
    return aci_op_pod, aci_ovs_pod, aci_host_pod, aci_controller_pod


def _verify_aci_pod_status(aci_ovs_pod, aci_host_pod,
                           aci_controller_pod, enable_updates):
    if enable_updates:
        _check_aci_pods_status("aci-containers-openvswitch",
                               exclude_pod_list=aci_ovs_pod)
        _check_aci_pods_status("aci-containers-host",
                               exclude_pod_list=aci_host_pod)
        _check_aci_pods_status("aci-containers-controller",
                               exclude_pod_list=aci_controller_pod)
    else:
        _check_aci_pods_status("aci-containers-openvswitch",
                               include_pod_list=aci_ovs_pod)
        _check_aci_pods_status("aci-containers-host",
                               include_pod_list=aci_host_pod)
        _check_aci_pods_status("aci-containers-controller",
                               include_pod_list=aci_controller_pod)


def _verify_deployment_images(image_version):
    LOG.info("Verifying acc provision operator container image of deployment "
             "aci-containers-operator, Expected image version is %s"
             % image_version)
    lib.check_aci_containers_image('deployment', 'aci-containers-operator',
                                   'acc-provision-operator',
                                   image_version,
                                   ACI_CONTAINERS_NAMESPACE)
    LOG.info("Verifying aci containers operator container image of deployment "
             "aci-containers-operator, Expected image version is %s"
             % image_version)
    lib.check_aci_containers_image('deployment', 'aci-containers-operator',
                                   'aci-containers-operator',
                                   image_version,
                                   ACI_CONTAINERS_NAMESPACE)


def _verify_aci_containers_images(aci_containers_operator_pod):
    # get acc provision version
    acc_provision_version = _get_acc_provision_version(
        aci_containers_operator_pod,
        ACI_CONTAINERS_NAMESPACE)
    # get version details from versions.yaml for acc provision version
    versions = _get_version_details(
        aci_containers_operator_pod, acc_provision_version)
    LOG.info("Version tags info: %s" % versions)
    # verify all the containers image version of aci-containers-host daemonset.
    lib.check_aci_containers_image('daemonset', 'aci-containers-host',
                                   'cnideploy',
                                   versions['cnideploy_version'],
                                   ACI_CONTAINERS_NAMESPACE,
                                   initcontainer=True)
    lib.check_aci_containers_image('daemonset', 'aci-containers-host',
                                   'aci-containers-host',
                                   versions['aci_containers_host_version'],
                                   ACI_CONTAINERS_NAMESPACE)
    lib.check_aci_containers_image('daemonset', 'aci-containers-host',
                                   'opflex-agent',
                                   versions['opflex_agent_version'],
                                   ACI_CONTAINERS_NAMESPACE)
    lib.check_aci_containers_image('daemonset', 'aci-containers-openvswitch',
                                   'aci-containers-openvswitch',
                                   versions['openvswitch_version'],
                                   ACI_CONTAINERS_NAMESPACE)
    LOG.info("Image version verification for all the containers of "
             "aci-containers-host daemonset is verified successfully.")


def _log_resource_utilization(stop, data):
    while True:
        if stop():
            break
        aci_op_pod = _get_aci_containers_operator_pod()
        cmd = "kubectl top pod %s -n %s | awk 'NR ==2 {print $2"  "$3}'" \
              % (aci_op_pod, ACI_CONTAINERS_NAMESPACE)
        res = subprocess.check_output(cmd, shell=True)
        if not res.decode():
            time.sleep(RESOURCE_PROFILING_INTERVAL)
            continue
        res = res.decode().split('m')
        cpu, memory = res[0] + 'm', res[1].split('M')[0] + 'Mi'
        data.append({'timestamp': datetime.now(),
                     'cpu': cpu, 'memory': memory})
        time.sleep(RESOURCE_PROFILING_INTERVAL)


def _display_data(resource_utilization_data):
    assert resource_utilization_data, "Empty data provided"
    LOG.info("Displaying resource utilization data "
             "of aci containers operator pod.")
    header = resource_utilization_data[0].keys()
    rows = [x.values() for x in resource_utilization_data]
    ab = tabulate.tabulate(rows, header, tablefmt='grid')
    print(ab)


def _get_aci_containers_image(obj_type, obj_name, container_name,
                              namespace=ACI_CONTAINERS_NAMESPACE):
    resource_details = KAPI.get_detail(obj_type,
                                       name=obj_name,
                                       namespace=namespace)
    container_details = resource_details['spec']['template'][
        'spec']['containers']
    for container in container_details:
        if container['name'] == container_name:
            return container['image']


def _get_acc_provision_input_manifest():
    accprovisioninput = KAPI.get_detail(
        obj_type='AccProvisionInput',
        name='accprovisioninput',
        namespace=ACI_CONTAINERS_NAMESPACE
    )
    return accprovisioninput


def _get_aci_containers_op_dep_details():
    aci_container_op_dep = KAPI.get_detail(
        obj_type='deployment',
        name='aci-containers-operator',
        namespace=ACI_CONTAINERS_NAMESPACE
    )
    return aci_container_op_dep


def _get_registry_images(manifest_file):
    return manifest_file['spec']['acc_provision_input']['registry']


def _create_and_apply_cr_manifest(manifest):
    with open(CR_FILE, 'w') as cr_file:
        cr_file.write(yaml.dump(manifest))
    cr_spec_config = manifest['spec']['acc_provision_input']
    LOG.info("Displaying accprovisioninput CR spec config:"
             "------ Dump: %s --------", pformat(cr_spec_config))
    KAPI.exec_cli_cmd(f"{KUBE_CLIENT} apply -f {CR_FILE}")


def _get_update_enable_config():
    enable_update = None
    manifest_file = _get_acc_provision_input_manifest()
    cr_spec = manifest_file['spec']['acc_provision_input']
    if "operator_managed_config" in cr_spec.keys():
        enable_update = cr_spec['operator_managed_config'].get(
            'enable_updates')
    return True if enable_update else False


def _set_update_enable_config(config_flag):
    assert type(config_flag) == bool, (
        'config_flag is not of a boolean type')
    op_managed_config = {'enable_updates': config_flag}
    manifest_file = _get_acc_provision_input_manifest()
    manifest_file['spec']['acc_provision_input'][
        'operator_managed_config'] = op_managed_config
    _create_and_apply_cr_manifest(manifest_file)
    LOG.info("enable_update config is set to %s" % config_flag)


def _get_pod_list_for_label(pod_label, namespace):
    pod_list = list()
    pod_label = 'name={}'.format(pod_label)
    temp = {'labels': pod_label}
    pods_detail = KAPI.get_detail('pod', namespace=namespace, **temp)
    for items in pods_detail['items']:
        pod_list.append(items['metadata']['name'])
    return pod_list


def _check_aci_pods_status(pod_label,
                           exclude_pod_list=None,
                           include_pod_list=None,
                           namespace=ACI_CONTAINERS_NAMESPACE):
    pod_label = 'name={}'.format(pod_label)
    temp = {'labels': pod_label}
    max_time = time.time() + MAX_WAITING_TIME
    LOG.info("Verify status of pods with label %s" % pod_label)
    while True:
        counter = 0
        pods_detail = KAPI.get_detail('pod', namespace=namespace, **temp)
        pod_count = len(pods_detail['items'])
        assert pods_detail, ("No POD found with label [%s]" % pod_label)
        for items in pods_detail['items']:
            pod_name = items['metadata']['name']
            pod_status = items['status']['phase']
            if exclude_pod_list:
                if pod_name not in exclude_pod_list \
                        and pod_status == "Running":
                    counter += 1
            elif include_pod_list:
                if pod_name in include_pod_list \
                        and pod_status == "Running":
                    counter += 1
            else:
                if pod_status == "Running":
                    counter += 1
        if counter >= pod_count:
            break
        if time.time() >= max_time:
            if exclude_pod_list:
                raise Exception("Updated ACI Pods with label[%s] are not in"
                                "Running state or not created" % pod_label)
            if include_pod_list:
                raise Exception("Expected ACI Pods [%s] are not in Running "
                                "state or not found" % include_pod_list)
        if exclude_pod_list:
            LOG.info("Waiting for updated ACI Pods with label[%s] "
                     " to come to Running state" % pod_label)
        time.sleep(INTERVAL)
    LOG.info("ACI pods status is verified for pod_label %s" % pod_label)
