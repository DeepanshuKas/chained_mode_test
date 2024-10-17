from distutils.command.config import config
import functools
import time
import pytest
import json
from json import JSONEncoder
from tests import lib
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.input.cfg import CRD_NAMESPACE


LOG = logger.get_logger(__name__)
RDCONFIG_NAME = 'routingdomain-config'
CONFIGMAP_NAME = 'aci-containers-config'
CONFIGMAP_NAMESPACE = 'aci-containers-system'
MAX_WAITING_TIME = 150
INTERVAL = 15


# subclass JSONEncoder
class DataEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


def patch_rdconfig_user_subnets(value):
    """ Patch the usersubnets field in RdConfig """
    kapi = KubeAPI()
    # Patching usersubnets in RDCONFIG
    LOG.info("Replacing usersubnets in RdConfig with %s", value)
    kapi.patch('rdconfig', RDCONFIG_NAME,
               {
                   'update_str': json.dumps(
                       [{"op": "add",
                         "path": "/spec/usersubnets",
                         "value": value}]),
                   'type': 'json'
               }, namespace=CRD_NAMESPACE)


def get_rdconfig():
    """ Get the RdConfig """
    try:
        return lib.get_detail('RdConfig',
                              name=RDCONFIG_NAME,
                              namespace=CRD_NAMESPACE)
    except Exception as e:
        if 'NotFound' in str(e.message):
            LOG.error("%s RdConfig does not exist", RDCONFIG_NAME)
        raise Exception("Failed to get rdconfig: %s" % e.message)


def patch_cm_controller_config(controller_config):
    """ Patch the controller config value in the Config Map """
    kapi = KubeAPI()

    # Encoding the data to JSON Serializable
    controller_config = json.dumps(
        controller_config, indent=4, cls=DataEncoder)

    patch_params = {'update_str': json.dumps(
        [{"op": "add",
          "path": "/data/controller-config",
          "value": controller_config}]),
        'type': 'json'}
    kapi.patch('ConfigMap', name=CONFIGMAP_NAME, patch_params=patch_params,
               namespace=CONFIGMAP_NAMESPACE)


def set_add_external_subnets_to_rdconfig(value=False):
    """ Set value to add-external-subnets-to-rdconfig \
        inside controller-config in Config Map. """
    """ value : True or False """

    LOG.info(
        "Setting the value of add-external-subnets-to-rdconfig in ConfigMap to %s", value)

    controller_config = lib.get_config_from_configmap('controller-config')

    # Changing Value of Add External Subnet
    controller_config["add-external-subnets-to-rdconfig"] = value

    patch_cm_controller_config(controller_config)


def preserve_rdconfig_and_config_map(func):
    """ Preserve original states of RdConfig and Config Map """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get original states
        LOG.info('Getting original rdconfig and CM state')
        rdconfig = get_rdconfig()
        controller_config = lib.get_config_from_configmap('controller-config')

        try:
            func(*args, **kwargs)

        finally:
            LOG.info("Restoring original state of rdconfig and CM")
            # Restore controller-config in Config Map
            patch_cm_controller_config(controller_config)
            # Restart Controller Pod
            lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)

            # Restore usersubnets in rdconfig
            usersubnets = rdconfig['spec'].get('usersubnets', [])
            patch_rdconfig_user_subnets(value=usersubnets)

    return wrapper


@preserve_rdconfig_and_config_map
def test_adding_extern_to_rdconfig_and_delete(base_fixture):
    """ To Validate Usersubnets before and after Deletion of RDCONFIG """
    """ Expectation: Usersubnets should match before and after deletion if \
                     add-external-subnets-to-rdconfig is set TRUE in Configmap """

    kapi = KubeAPI()
    # Remove all user subnets from rdconfig
    patch_rdconfig_user_subnets(value=[])

    # Set add-external-subnets-to-rdconfig to True in Config Map
    set_add_external_subnets_to_rdconfig(True)

    # Restart Controller Pod
    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)

    max_time = time.time() + MAX_WAITING_TIME
    while True:
        rdconfig = get_rdconfig()
        user_subnets = rdconfig['spec'].get('usersubnets', [])
        LOG.debug("Usersubnets: %s", user_subnets)
        if len(user_subnets) > 0:
            break
        assert time.time() < max_time, "Timed out waiting for usersubnets to be populated"
        time.sleep(5)

    LOG.info("Usersubnets before deletion: %s", user_subnets)

    # Delete RDCONFIG
    LOG.info("Deleting %s RdConfig", RDCONFIG_NAME)
    kapi.delete_object('RdConfig',
                       name=RDCONFIG_NAME,
                       namespace=CRD_NAMESPACE)

    max_time = time.time() + MAX_WAITING_TIME
    while True:
        try:
            rdconfig = get_rdconfig()
            break
        except Exception:
            LOG.debug(
                "%s RdConfig not found. Retrying after 5 seconds", RDCONFIG_NAME)
            time.sleep(5)
            assert time.time() < max_time, "Timed out trying to get RdConfig"

    user_subnets_new = rdconfig['spec'].get('usersubnets')
    LOG.info("Usersubnets in RdConfig after deletion: %s", user_subnets_new)

    # Check if Test Case doesn't meet the expectation
    assert set(user_subnets) == set(
        user_subnets_new), "Usersubnets mismatch before and after Rdconfig Deletion."
    LOG.info("Usersubnets are same before and after RdConfig Deletion")


@preserve_rdconfig_and_config_map
def test_adding_extern_to_rdconfig_true(base_fixture):
    """ To Validate Usersubnets contains extern-static and extern dynamic from Configmap """
    """ Expectation: extern-static and extern dynamic should present in RDCONFIG usersubnets if \
                     add-external-subnets-to-rdconfig is set True in Configmap """

    controller_config = lib.get_config_from_configmap('controller-config')
    # getting extern-dynamic and extern-static value from Config Map
    extern_dynamic = controller_config["extern-dynamic"]
    extern_static = controller_config["extern-static"]
    LOG.info("Subnets in Config Map:  extern_static: %s, extern_dynamic: %s",
             extern_static, extern_dynamic)

    # Remove all user subnets
    patch_rdconfig_user_subnets(value=[])

    # Set add-external-subnets-to-rdconfig to True in Config Map
    set_add_external_subnets_to_rdconfig(True)

    # Restart Controller Pod
    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)

    max_time = time.time() + MAX_WAITING_TIME
    while True:
        rdconfig = get_rdconfig()
        user_subnets = rdconfig['spec'].get('usersubnets')
        LOG.info("Subnets in rdconfig: %s", user_subnets)

        if user_subnets:
            if isinstance(extern_dynamic, str):
                extern_dynamic = [extern_dynamic]
            extern_dynamic_set = set(extern_dynamic)
            if isinstance(extern_static, str):
                extern_static = [extern_static]
            extern_static_set = set(extern_static)
            if extern_dynamic_set.issubset(user_subnets) and extern_static_set.issubset(user_subnets):
                LOG.info("Extern Dynamic and Static are present in RDCONFIG")
                break

        assert time.time() < max_time, "Extern Dynamic and Static are not present in RDCONFIG usersubnets. Usersubnets present: %s" % user_subnets


@preserve_rdconfig_and_config_map
def test_adding_extern_to_rdconfig_false(base_fixture):
    """ To Validate usersubnets in RDCONFIG is Empty """
    """ Expectation: usersubnets in RDCONFIG should be empty if \
                     add-external-subnets-to-rdconfig is set False in Configmap """

    # Set add-external-subnets-to-rdconfig to False in Config Map
    set_add_external_subnets_to_rdconfig()

    # Restart Controller Pod
    lib.restart_controller(namespace=CONFIGMAP_NAMESPACE)

    # Remove all user subnets
    patch_rdconfig_user_subnets(value=[])

    # Check if the usersubnets changes after a wait
    time.sleep(120)
    rdconfig = get_rdconfig()
    user_subnets = rdconfig['spec'].get('usersubnets', [])

    # Fail the test if the usersubnets changes
    assert len(user_subnets) == 0, "Usersubnets in RDCONFIG is not empty"

    LOG.info("Usersubnets in RDCONFIG is Empty, as Expected")


def test_if_rdconfig_exists(base_fixture):
    try:
        get_rdconfig()
    except Exception as e:
        assert False, "Validating rdconfig failed. Reason: %s" % e
    LOG.info("%s RdConfig exists", RDCONFIG_NAME)


def test_rdconfig_creation_after_deletion(base_fixture):
    kapi = KubeAPI()

    rdconfig = lib.get_detail('RdConfig',
                              name=RDCONFIG_NAME,
                              namespace=CRD_NAMESPACE)

    LOG.info("Deleting %s RdConfig", RDCONFIG_NAME)

    kapi.delete_object('RdConfig',
                       name=RDCONFIG_NAME,
                       namespace=CRD_NAMESPACE)

    max_time = time.time() + MAX_WAITING_TIME
    while True:

        rdconfig_details = kapi.get_detail('RdConfig',
                                           namespace=CRD_NAMESPACE)

        if len(rdconfig_details.get('items')) != 0:
            for new_rdconfig in rdconfig_details['items']:
                if new_rdconfig['metadata']['name'] == RDCONFIG_NAME:
                    for subnettype in rdconfig['spec']:
                        mismatch = False
                        if (subnettype not in new_rdconfig['spec']):
                            if len(rdconfig['spec'][subnettype]) > 0:
                                mismatch = True
                        elif (sorted(new_rdconfig['spec'][subnettype]) != sorted(rdconfig['spec'][subnettype])):
                            mismatch = True

                        if mismatch:
                            LOG.error(
                                "Mismatch in spec of %s RdConfig before and after deletion", RDCONFIG_NAME)
                            LOG.info(
                                "rdconfig spec before deletion : %s", rdconfig['spec'])
                            LOG.info("rdconfig spec after deletion : %s",
                                     new_rdconfig['spec'])
                            assert False, (
                                "Validating rdconfig after deletion failed, Reason: Mismatch in spec of %s RdConfig before and after deletion", RDCONFIG_NAME)
                    LOG.info(
                        "Validated creation of %s RdConfig after deletion", RDCONFIG_NAME)
                    return

        if time.time() >= max_time:
            LOG.error("%s RdConfig didnot come up after deletion", RDCONFIG_NAME)
            assert False, ("Validating rdconfig after deletion failed, Reason:%s RdConfig is not up after deletion", RDCONFIG_NAME)

        time.sleep(INTERVAL)
