import os
import shutil
from datetime import datetime
from uuid import uuid4

import pytest

from acc_pyutils import logger
from acc_pyutils.api import KubeAPI
from acc_pyutils.utils import edit_file, get_py_exec, \
    update_http_server_version
from tests import lib
from tests.input.cfg import CLEAN_IF_FAIL, REMOTE_ROUTER
from tests.server_utils import ServerUtils
from tests.template_utils import GEN_TEST_DIR
from threading import Thread

LOG = logger.get_logger(__name__)
TEMPLATE_PATH = os.path.abspath('tests/templates')

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

def pytest_addoption(parser):
    parser.addoption(
        "--server_ip", action="store", default="10.3.0.252",
        help="provide server ip"
        )
    parser.addoption(
        "--server_port", action="store", default="80", help="server port"
        )
    parser.addoption(
        "--hpp_optimization", action="store", default="false", help="hpp optimization"
        )
    parser.addoption(
        "--hpp_direct", action="store", default="false", help="hpp direct"
        )

@pytest.fixture
def server_ip(request):
    return request.config.getoption("--server_ip")


@pytest.fixture
def server_port(request):
    return request.config.getoption("--server_port")

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture(scope="function")
def base_fixture(request):
    LOG.info('-------- Test - %s started --------' % request.node.name)
    shared_info = dict()

    @request.addfinalizer
    def delete_resources():
        LOG.info('........ Cleanup for - %s started ........' %
                 request.node.name)
        log_test_info(shared_info)
        lib.kill_server()
        lib.kill_tcpdump()
        if request.node.rep_call.failed and not CLEAN_IF_FAIL:
            return
        del_resources(shared_info, request.node.name)
        log_test_status(request)

    return shared_info


def del_resources(shared_info, test):
    kapi = KubeAPI()
    if lib.check_chained_mode():
        for label, manifest_dir in shared_info.get('delete_info', []):
            kapi.delete_by_label(label, manifest_dir)
    else:
        threads = []
        for label, manifest_dir in shared_info.get('delete_info', []):
            thread = PropagatingThread(target=kapi.delete_by_label, args=(label, manifest_dir))
            threads.extend([thread])

        for thread in threads:
            thread.start()

        for thread in threads:
            try:
                thread.join()
            except Exception as e:
                LOG.error(f"Thread {thread} raised an exception: {e}")
                assert False, ("Thread execution failed")
    LOG.info('........ Cleanup done for - %s  ........' % test)


def log_test_info(test_info):
    test_dirs = []
    for _, manifest_dir in test_info.get('delete_info', []):
        test_dirs.append(manifest_dir)
    LOG.info('........ Test tmp directories - %s ........' % test_dirs)


def log_test_status(request):
    result = 'failed' if request.node.rep_call.failed else 'passed'
    if result == 'failed':
        LOG.error('-------- Test - %s %s --------' % (request.node.name,
                                                      result))
        return
    LOG.info('-------- Test - %s %s --------' % (request.node.name,
                                                 result))


@pytest.fixture(scope="session", autouse=True)
def clean_gen_templates(request):
    def fin():
        if not CLEAN_IF_FAIL:
            LOG.info("Generated template can be found at - %s" % GEN_TEST_DIR)
            return
        LOG.info("Deleting generated templates ...")
        try:
            shutil.rmtree(GEN_TEST_DIR)
        except OSError as e:
            LOG.warning('Directory -%s deletion failed - %s' % (GEN_TEST_DIR,
                                                                e.strerror))
        LOG.info("Deleted generated templates")
    request.addfinalizer(fin)


@pytest.fixture
def gen_template_name():
    if not os.path.exists(GEN_TEST_DIR):
        os.mkdir(GEN_TEST_DIR)

    def generate_name(*args, **kwargs):
        name = args[0].replace('-', '_')
        file_name = ''.join((name,
                             datetime.now().strftime('_%Y%m%d_%H%M%S'),
                             str(uuid4()).split('-')[0],
                             '.yaml'))
        return GEN_TEST_DIR + '/%s' % file_name

    return generate_name


def pytest_configure(config):
    _PYTHON, srv = None, None
    if REMOTE_ROUTER:
        srv = ServerUtils().get_external_router()
        _PYTHON = get_py_exec(srv)
    else:
        _PYTHON = get_py_exec()
    if not _PYTHON:
        raise Exception("Python not installed on router node.")
    update_config_file(_PYTHON)
    update_http_server_version('tests/input/cfg.py', _PYTHON, srv)


def update_config_file(py_str):
    cfg_file = os.path.abspath('tests/input/cfg.py')
    bkup_file = os.path.abspath('tests/input/') + "/cfg.bak"
    if not os.path.exists(bkup_file):
        with open(bkup_file, 'w+'): pass
    shutil.copyfile(cfg_file, bkup_file)
    edit_file(cfg_file, "PYTHON_EXEC", 'PYTHON_EXEC = \'%s\'' % py_str)


