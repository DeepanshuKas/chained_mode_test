import os
import time
import pytest
import random

import tests.vm_migration_helper as vm_helper
from acc_pyutils import logger
from collections import defaultdict
from tests import lib
import tests.scale_test_helper as scale_helper
import tests.input.cfg as cfg
LOG = logger.get_logger(__name__)
DATA_DIR = os.path.abspath('tests/test_data')
LEAF_TO_COMPUTE_HOST_MAPPING = defaultdict(list)
MAX_MIGRATION_COUNT = vm_helper.DEFAULT_MAX_MIGRATION_COUNT
NODE_WAIT_TIMEOUT = vm_helper.DEFAULT_NODE_WAIT_TIMEOUT
TRAFFIC_RESUME_TIMEOUT = vm_helper.DEFAULT_TRAFFIC_RESUME_TIMEOUT
VM_MIGRATION_TIMEOUT = vm_helper.DEFAULT_VM_MIGRATION_TIMEOUT


@pytest.mark.skipif(not lib.is_openstack(), reason="Setup : "
                                "Skipping the Testcase as it needs Openstack setup")
@pytest.mark.usefixtures("clean_gen_templates")
def test_inter_and_intra_leaf_pair(base_fixture, gen_template_name):
    """ Test datapath connectivity in Intra & Inter leaf Pair VM Migrations

    This test performs below steps.
    1. Get Leaf to Compute Host mapping.
    2. Create resources to test datapath.
    3. Check datapath connectivity before migration
    4. verify_vm_live_migration_test for Intra-Leaf Pair Case
    5. verify_vm_live_migration_test for Inter-Leaf Pair Case
    6. Post migration Delete resources created to test datapath 
    7. Post Migration create the resources and check datapath connectivity
    8. Also dump the summary of VM Live Migration test
    """
    result_summary = list()
    resources = dict()
    multi_lp = False
    namespaces = ["test-vm-ns"]
    
    # Update global LEAF_TO_COMPUTE_HOST_MAPPING
    global LEAF_TO_COMPUTE_HOST_MAPPING
    global MAX_MIGRATION_COUNT
    global NODE_WAIT_TIMEOUT
    global TRAFFIC_RESUME_TIMEOUT
    global VM_MIGRATION_TIMEOUT
    NODE_WAIT_TIMEOUT =  getattr(cfg, 'NODE_WAIT_TIMEOUT', NODE_WAIT_TIMEOUT)
    TRAFFIC_RESUME_TIMEOUT = getattr(cfg, 'TRAFFIC_RESUME_TIMEOUT', TRAFFIC_RESUME_TIMEOUT)
    VM_MIGRATION_TIMEOUT =  getattr(cfg, 'VM_MIGRATION_TIMEOUT', VM_MIGRATION_TIMEOUT)
    # For debugging purpose we can specify node list to test
    test_node_list = getattr(cfg, 'NODE_LIST_TO_MIGRATE', [])
    nodename = None
    if test_node_list:
        MAX_MIGRATION_COUNT = len(test_node_list)
        if MAX_MIGRATION_COUNT == 1:
            nodename = test_node_list[0]
    else :
        MAX_MIGRATION_COUNT = getattr(cfg, 'MAX_MIGRATION_COUNT', 1)

    LOG.info("MAX_MIGRATION_COUNT %d NODE_WAIT_TIMEOUT %d TRAFFIC_RESUME_TIMEOUT %d test_node_list %s" %
             (MAX_MIGRATION_COUNT, NODE_WAIT_TIMEOUT, TRAFFIC_RESUME_TIMEOUT, test_node_list))

    LEAF_TO_COMPUTE_HOST_MAPPING = vm_helper.get_leaf_to_compute_host_mapping()
    if len(LEAF_TO_COMPUTE_HOST_MAPPING) == 0:
        assert False, ("Failed to get Leaf to Host Mapping")
    elif len(LEAF_TO_COMPUTE_HOST_MAPPING) == 1:
        LOG.info("Single LeafPair found, Will Run Intra-Leaf Test only")
    else :
        multi_lp = True

    try:
        # Create Test resources
        scale_helper.create_datapath_resources_in_parallel(
            base_fixture, namespaces, resources, nodename=nodename)
        # Run Traffic test before VM Migration
        scale_helper.check_datapath_connectivity(
            base_fixture, namespaces, resources, nodename=nodename)

        # Intra-Leaf Migration
        LOG.info("Running Intra-Leaf VM Migration Test..")
        verify_vm_live_migration_test(
            base_fixture, resources, namespaces, result_summary, test_node_list=test_node_list, is_interleaf=False)
        # Inter-Leaf Migration
        if multi_lp:
            LOG.info("Running Inter-Leaf VM Migration Test..")
            verify_vm_live_migration_test(
                base_fixture, resources, namespaces, result_summary, test_node_list=test_node_list, is_interleaf=True)

        # Post Migration Test
        scale_helper.delete_datapath_resources(base_fixture, resources)
        scale_helper.create_resources_and_check_datapath_connectivity(
            base_fixture, namespaces)
    except Exception as ex:
        LOG.error("VN Migration Test Failed : %s" % ex)
        scale_helper.delete_datapath_resources(base_fixture, resources)
        raise
    finally:
        test_status = vm_helper.dump_migration_stats(result_summary)
        assert test_status, "VM Migration test Failed!!"

# Helper functions
def verify_vm_live_migration_test(
        base_fixture, resources, namespaces, result_summary, test_node_list=[], is_interleaf=True):
    """ Test Openstack VM Live Migration for Intra or Inter leaf Pair case

    This test performs below steps.
    1. Get list of nodes available on cluser
    2. Based on is_interleaf get leaf and target host for VM live migration.
    3. Migrate the VM on selected target host.
    4. Run Traffic test to check the connectivity during migration.
    5. Once the Migration completed, Verify L4/L7 programming time(Inter-Leaf Pair Case).
    6. Check for node ready and get the time. 
    7. Check for traffic resume and get the time. 
    8. Run Traffic test after migration.
    9. Return the summary of VM live migration test
    """
    MIGRATION_COUNT = 0
    migration_type = "Inter-Leaf" if is_interleaf else "Intra-Leaf"
    
    oapi = vm_helper.OpenstackAPI()
    nodes = oapi.list_nodes_with_info()
    ready_nodes =  lib.get_all_nodes_hostname_with_ready_state()
    LOG.info("MAX_MIGRATION_COUNT %d" % MAX_MIGRATION_COUNT)
    for src_node_name, node_details in nodes.items():
        if src_node_name not in ready_nodes:
            LOG.warning("src_node_name %s not Ready" % src_node_name)
            continue
        if test_node_list and src_node_name not in test_node_list:
            continue
        src_compute_host = node_details['Compute Host']
        src_leaf = get_host_leaf(src_compute_host)
        if is_interleaf:
            target_leaf, dest_compute_host = get_leaf_and_host_for_inter_leaf_test(node_details)
        else:
            target_leaf, dest_compute_host = get_leaf_and_host_for_intra_leaf_test(node_details)
        if dest_compute_host is None:
            continue
        failed = passed = warn = 0
        migration_started = False
        target_node_id = node_details['ID']
        lp = vm_helper.get_node_opflexODev_leafPair(src_node_name)
        max_time = time.time() + VM_MIGRATION_TIMEOUT
        start_time = time.time()
        migration_info = {'type' : migration_type, 'node' : src_node_name,
                          'src_compute_host' : src_compute_host,
                          'dest_compute_host' : dest_compute_host,
                          'src_leaf' : src_leaf, 'target_leaf' : target_leaf}
        LOG.info(migration_info)
        result_summary.append(migration_info)
        try:
            ret = oapi.vm_live_migrate(target_node_id, dest_compute_host)
            migration_started = True
        except Exception as ex:
            LOG.error("Openstack VM Live migration failed : %s" % ex)
            migration_info.update({'migration_status' : 'FAILED'})
            pass
        if not migration_started:
            continue
        while True:
            status = oapi.get_node_status(target_node_id)
            LOG.info("%s Live migration of node %s from host %s to host %s status is: %s" %
             (migration_type, src_node_name, src_compute_host, dest_compute_host, status))
            if status == "ACTIVE" or time.time() >= max_time:
                if status == "ACTIVE":
                    # Verify node migrated to correct compute host
                    _, current_compute_host = get_node_leaf_and_host(src_node_name)
                    if current_compute_host != dest_compute_host:
                        migration_info.update({'migration_status' : 'FAILED'})
                        assert False, (
                            "Migration status SUCCESS, but node %s not migrated to correct host %s current host %s"
                            % (src_node_name, dest_compute_host, current_compute_host))
                    time_diff = int(time.time() - start_time)
                    migration_info.update({'migration_status' : 'SUCCESS'})
                    migration_info.update({'migration_time' : time_diff})
                    if is_interleaf:
                        created, prog_time = vm_helper.get_node_opflexODev_prog_time(
                            src_node_name, lp, wait_for_delete=False)
                        migration_info.update({'opflexODev_creation' : 'SUCCESS' if created else 'FAILED'})
                        assert created, ("Failed to create new opflexODev")
                        migration_info.update({'opflexODev_prog_time' : prog_time})

                        sync, time_diff = vm_helper.validate_node_opflexODev_and_L4L7_device_sync(src_node_name)
                        migration_info.update({'opflexODev_and_L4L7Device_sync' : 'SUCCESS' if sync else 'FAILED'})
                        assert sync, ("opflexODev and L4L7Device information are out of sync!")
                        migration_info.update({'opflexODev_and_L4L7Device_sync_time' : time_diff})
                else: #TIMEOUT
                    migration_info.update({'migration_status' : 'FAILED'})
                MIGRATION_COUNT += 1
                break
            # Run Traffic test during migration
            traffic_resumed, time_diff = scale_helper.check_for_basic_traffic(
                resources, namespaces[0], nodename=src_node_name, timeout=30)
            if traffic_resumed:
                passed = passed + 1
            else :
                status = oapi.get_node_status(target_node_id)
                LOG.warning("Connectivity lost, migration status is: %s" % status)
                if status != "ACTIVE":
                    # Connectivity lost during Migration
                    failed = failed + 1
                else:
                    # Connectivity lost post Migration
                    warn = warn + 1
            time.sleep(vm_helper.INTERVAL)
        migration_info.update({'Traffic_Test_During_Migration' : {'Passed' : passed, 'Failed' : failed, 'Warning' : warn}})
        LOG.info("Migrated instance %s status is: %s completed in %d" %
                 (src_node_name, status, (time.time() - start_time)))
        assert status == 'ACTIVE', ("%s Migration Failed for node %s" %
                                    (migration_type, src_node_name)) 

        is_ready, time_diff = lib.wait_till_node_ready(src_node_name, timeout=NODE_WAIT_TIMEOUT)
        assert is_ready, ("Node %s not Ready after migration" % src_node_name)
        migration_info.update({'node_ready_time' : time_diff})
        
        traffic_resumed, time_diff = scale_helper.check_for_basic_traffic(
            resources, namespaces[0], nodename=src_node_name)
        assert traffic_resumed, ("Traffic not resumed after migration")
        migration_info.update({'traffic_resume_time' : time_diff})
        
        # Run Traffic test after migration
        try:
            LOG.info("Running Test After %s migration" % migration_type)
            scale_helper.check_datapath_connectivity(
                base_fixture, namespaces, resources, nodename=src_node_name)
            migration_info.update({'Traffic_Test_Post_Migration' : "SUCCESS"})
        except Exception as ex:
            LOG.warning("Traffic test after migration failed : %s" % ex)
            migration_info.update({'Traffic_Test_Post_Migration' : "FAILED"})
            pass
        LOG.info("Current MIGRATION_COUNT : %d" % MIGRATION_COUNT)
        if MIGRATION_COUNT >= MAX_MIGRATION_COUNT:
            break 

def get_host_leaf(compute_host):
    """ Get compute host leaf from LEAF_TO_COMPUTE_HOST_MAPPING """
    for leaf, hosts in LEAF_TO_COMPUTE_HOST_MAPPING.items():
        if compute_host in hosts:
            return leaf
    return None

def get_node_leaf_and_host(node_name):
    """ Get leaf and compute host of node"""
    oapi = vm_helper.OpenstackAPI()
    compute_host = oapi.get_node_details(node_name)['Compute Host']
    leaf = get_host_leaf(compute_host)
    return leaf, compute_host


def get_leaf_and_host_for_intra_leaf_test(node_details):
    """ Check and get valid leaf, and target host for Intra-Leaf Pair case 
        Returns Same leaf Pair different host """
    src_compute_host = node_details['Compute Host']
    src_leaf = get_host_leaf(src_compute_host)
    dest_compute_hosts = LEAF_TO_COMPUTE_HOST_MAPPING.get(src_leaf, [])
    random.shuffle(dest_compute_hosts)
    for dest_compute_host in dest_compute_hosts :
        if src_compute_host != dest_compute_host:
            if is_valid_target_host_for_migration(node_details, dest_compute_host):
                return src_leaf, dest_compute_host
    return None, None

def get_leaf_and_host_for_inter_leaf_test(node_details):
    """ Check and get valid leaf, and target host for Inter-Leaf Pair case
        Returns different leaf Pair any valid node
    """
    src_compute_host = node_details['Compute Host']
    src_leaf = get_host_leaf(src_compute_host)
    for target_leaf, dest_compute_hosts in LEAF_TO_COMPUTE_HOST_MAPPING.items():
        if src_leaf == target_leaf:
            continue
        random.shuffle(dest_compute_hosts)
        for dest_compute_host in dest_compute_hosts:
            if src_compute_host != dest_compute_host:
                if is_valid_target_host_for_migration(node_details, dest_compute_host):
                    return target_leaf, dest_compute_host
    return None, None

def is_valid_target_host_for_migration(node_details, host_name):
    """ Validate target host for VM migration based on available
        resources on compute host and required resources for node
    """
    oapi = vm_helper.OpenstackAPI()
    is_valid = list()
    free_resc_info = oapi.get_host_free_resources_info(host_name)
    req_resc_info = node_details['Specs']
    for resc, value in req_resc_info.items():
        value = int(value)
        free_resc = int(free_resc_info.get(resc, 0))
        LOG.debug("%s : %d : %d" % (resc, free_resc, value))
        if free_resc >= value:
            is_valid.append(True)
        else:
            is_valid.append(False)
            LOG.warning("%s : Available %d Required %d" % (resc, free_resc, value))
    LOG.info("Node %s Host %s %s valid %r" %
             (node_details['name'], host_name, is_valid, all(is_valid)))
    return all(is_valid)
