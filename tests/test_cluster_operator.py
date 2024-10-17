import time

import pytest
import subprocess
import os
import json

from tests import lib_helper, lib
from acc_pyutils.api import KubeAPI
from acc_pyutils import logger
from tests.input.cfg import CRD_NAMESPACE
from acc_pyutils import condition, kube_objects as k_obj, logger, utils
from acc_pyutils.acc_cfg import get_kube_client


LOG = logger.get_logger(__name__)

def isUnhealthy(condition_type):
    for j in range(0, len(condition_type) ):
        if condition_type[j]['type'] == 'Available' and condition_type[j]['status'] != 'True':
            return True, condition_type[j]['message']
        if condition_type[j]['type'] == 'Progressing' and condition_type[j]['status'] != 'False':
            return True, condition_type[j]['message']
        if condition_type[j]['type'] == 'Degraded' and condition_type[j]['status'] != 'False':
            return True, condition_type[j]['message']
    return False, ""

@pytest.mark.skipif(get_kube_client() != 'oc', reason='openshift related')
def test_list_unhealthy(base_fixture):
    LOG.info("Checking openshift cluster operator health status...")
    kapi = KubeAPI()
    data = kapi.get_detail('ClusterOperator')
    unhealthy_list = {}
    for i in range(0, len(data['items']) -1 ):
        res, message = isUnhealthy(data['items'][i]['status']['conditions'])
        if res:
            unhealthy_list[data['items'][i]['metadata']['name']] = message

    assert len(unhealthy_list) == 0, ("Unhealthy operator details :-  %s " % unhealthy_list)