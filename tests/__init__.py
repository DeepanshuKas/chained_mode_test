import os

import yaml

from acc_pyutils.utils import logger

LOG = logger.get_logger(__name__)

TEST_TUNEUP_FILE = os.path.abspath("tests/input/test_tuneup.yaml")


def read_yaml(input_file):
    with open(TEST_TUNEUP_FILE, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            LOG.error("Failed to load file - %s . %s" % (input_file, e))
            raise


try:
    test_tuneup = read_yaml(TEST_TUNEUP_FILE)
except FileNotFoundError:
    LOG.info("test_tuneup.yaml not provided by user")
    test_tuneup = {}
