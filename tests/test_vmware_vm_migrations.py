import os
import time
import pytest
import inspect

from acc_pyutils import logger
from tests import lib
import tests.input.cfg as cfg
import tests.vm_migration_helper as vm_helper
import tests.scale_test_helper as scale_helper
from tests.vcenter_apis import get_vcenter_obj

LOG = logger.get_logger(__name__)
CONFIG_FILE = os.path.abspath('tests/input/cfg.py')

MAX_MIGRATION_COUNT = vm_helper.DEFAULT_MAX_MIGRATION_COUNT
NODE_WAIT_TIMEOUT = vm_helper.DEFAULT_NODE_WAIT_TIMEOUT
TRAFFIC_RESUME_TIMEOUT = vm_helper.DEFAULT_TRAFFIC_RESUME_TIMEOUT
VM_MIGRATION_TIMEOUT = vm_helper.DEFAULT_VM_MIGRATION_TIMEOUT
NODE_LIST_TO_MIGRATE = []

pytestmark = pytest.mark.skipif(lib.is_openstack(), reason="Setup : "
                                "Skipping the Testcase as it needs VMWare setup")
# Enable Mutipod Test
def is_multipod():
    multipod_test =  getattr(cfg, 'MULTIPOD_TEST', False)
    return multipod_test is True

# Updates the VM Migration Global Variables
def update_vm_migraion_global(vc):
    global MAX_MIGRATION_COUNT
    global NODE_WAIT_TIMEOUT
    global TRAFFIC_RESUME_TIMEOUT
    global NODE_LIST_TO_MIGRATE
    global VM_MIGRATION_TIMEOUT
    if cfg.VC_CONFIG.get("HOST_DETAILS"):
        LOG.info("Taking HOST_DETAILS from %s", CONFIG_FILE)
        leaf_to_host = cfg.VC_CONFIG.get("HOST_DETAILS")
    else:
        LOG.info("Automatically getiing HOST_DETAILS")
        leaf_to_host = vc.get_leaf_to_compute_host_mapping()

    assert len(leaf_to_host) != 0, ("Failed to get Leaf to Host Mapping")
    vc.set_leaf_to_host(leaf_to_host)
    vc.dump_leaf_to_host()

    NODE_WAIT_TIMEOUT =  getattr(cfg, 'NODE_WAIT_TIMEOUT', NODE_WAIT_TIMEOUT)
    TRAFFIC_RESUME_TIMEOUT = getattr(cfg, 'TRAFFIC_RESUME_TIMEOUT', TRAFFIC_RESUME_TIMEOUT)
    VM_MIGRATION_TIMEOUT =  getattr(cfg, 'VM_MIGRATION_TIMEOUT', VM_MIGRATION_TIMEOUT)
    # For debugging purpose we can specify node list to test
    NODE_LIST_TO_MIGRATE = getattr(cfg, 'NODE_LIST_TO_MIGRATE', [])
    nodename = None
    if NODE_LIST_TO_MIGRATE:
        MAX_MIGRATION_COUNT = len(NODE_LIST_TO_MIGRATE)
        if MAX_MIGRATION_COUNT == 1:
            nodename = NODE_LIST_TO_MIGRATE[0]
    else :
        MAX_MIGRATION_COUNT = getattr(cfg, 'MAX_MIGRATION_COUNT', 1)

    LOG.info("MAX_MIGRATION_COUNT %d TIMEOUT NODE_WAIT %d TRAFFIC_RESUME %d VM_MIGRATION %d",
             MAX_MIGRATION_COUNT, NODE_WAIT_TIMEOUT, TRAFFIC_RESUME_TIMEOUT, VM_MIGRATION_TIMEOUT)
    return {'nodename' : nodename, 'inter_leaf' : vc.is_valid_cluster_for_inter_leaf_migration(),
            'intra_leaf' : vc.is_valid_cluster_for_intra_leaf_migration()}

# Helper functions
def verify_vm_live_migration_test(
        base_fixture, vc, resources, namespaces, result_summary, **kwargs):
    """ Test VMware VM Live Migration for Intra or Inter leaf Pair case

    This test performs below steps.
    1. Based on inter_leaf get leaf and target host for VM live migration.
    2. Migrate the VM on selected target host.
    3. Run Traffic test to check the connectivity during migration.
    4. Once the Migration completed, Verify L4/L7 programming time(Inter-Leaf Pair Case).
    5. Check for node ready and get the time.
    6. Check for traffic resume and get the time.
    7. Run Traffic test after migration.
    """
    nodes_to_migrate = kwargs.get("nodes_to_migrate", None)
    dest_host = kwargs.get("dest_host", '')
    inter_leaf = kwargs.get("inter_leaf", True)
    migration_count = 0
    migration_type = "Inter-Leaf" if inter_leaf else "Intra-Leaf"
    if nodes_to_migrate is None:
        nodes_to_migrate =  vc.get_valid_node_for_migration(inter_leaf=inter_leaf)
    for src_node_name in nodes_to_migrate:
        migration_started = False
        if NODE_LIST_TO_MIGRATE and src_node_name not in NODE_LIST_TO_MIGRATE:
            continue
        node_host =  vc.get_node_host(src_node_name)
        src_leaf, src_host_details = vc.get_host_details(node_host)
        lp = vm_helper.get_node_opflexODev_leafPair(src_node_name)
        if len(dest_host) == 0:
            if inter_leaf:
                target_leaf, dest = vc.get_leaf_and_host_for_inter_leaf_test(node_host)
            else: #intra_leaf
                target_leaf, dest = vc.get_leaf_and_host_for_intra_leaf_test(node_host)
        else:
                target_leaf, dest = vc.get_host_details(dest_host)
        if len(dest) == 0:
            LOG.warning("Node %s is Not Valid for %s Migration", src_node_name, migration_type)
            continue
        LOG.info("%s Live migration From Host %s to Host %s", src_node_name, node_host, dest)
        migration_info = {'type' : migration_type, 'node' : src_node_name,
                        'src_host' : src_host_details,
                        'dest_host' : dest,
                        'src_leaf' : src_leaf, 'target_leaf' : target_leaf}
        LOG.info(migration_info)
        result_summary.append(migration_info)
        try:
            task = vc.live_migrate_node(src_node_name, dest)
            migration_started = True
        except Exception as ex:
            LOG.error("VWWare VM Live migration failed : %s", ex)
            migration_info.update({'migration_status' : 'FAILED'})
            pass
        if not migration_started:
            continue
        max_time = time.time() + VM_MIGRATION_TIMEOUT
        failed = passed = warn = 0
        while True:
            task_info = task.get_info()
            status = task_info.status
            completed = task_info.progress.completed
            LOG.info("%s migration Status %s Progress : %d%%", src_node_name, status, completed)
            if status != 'RUNNING' and status != 'PENDING' or time.time() >= max_time:
                break
            # check traffic during migration
            traffic_resumed, time_diff = scale_helper.check_for_basic_traffic(
                resources, namespaces[0], nodename=src_node_name, timeout=30)
            if traffic_resumed:
                passed = passed + 1
            else:
                task_info = task.get_info()
                completed = task_info.progress.completed
                LOG.info("Task Info : %s Progress : %d%%", task_info, completed)
                if completed != 100:
                    # Connectivity lost during Migration
                    failed = failed + 1
                    LOG.warning(task_info)
                else:
                    # Connectivity lost post Migration
                    warn = warn + 1
            time.sleep(vm_helper.INTERVAL)

        migration_count += 1
        migration_info.update({'Traffic_Test_During_Migration' :
                               {'Passed' : passed, 'Failed' : failed, 'Warning' : warn}})
        if status != 'SUCCEEDED':
            migration_info.update({'migration_status' : 'FAILED'})
            assert False, ("VM Migration Failed Status %s!", status)
        else :
            time_diff = task.get_info().end_time - task.get_info().start_time
            migration_info.update({'migration_status' : 'SUCCESS'})
            migration_info.update({'migration_time' : time_diff})
            # Verify node migrated to correct compute host
            current_compute_host = vc.get_node_host(src_node_name)
            if current_compute_host != dest.get('host'):
                migration_info.update({'migration_status' : 'FAILED'})
                assert False, ("Migration status SUCCESS, but node %s not migrated to correct host %s current host %s",
                               src_node_name, dest.get('host'), current_compute_host)

        LOG.info("Migrated node %s status is: %s Completed in %s",
                 src_node_name, status, task.get_info().end_time - task.get_info().start_time)
        if inter_leaf:
            created, prog_time = vm_helper.get_node_opflexODev_prog_time(src_node_name, lp)
            assert created, ("Failed to create new opflexODev!")
            LOG.info(prog_time)
            migration_info.update({'opflexODev_creation' : 'SUCCESS' if created else 'FAILED'})
            assert created, ("Failed to create new opflexODev")
            migration_info.update({'opflexODev_prog_time' : prog_time})
            sync, time_diff = vm_helper.validate_node_opflexODev_and_L4L7_device_sync(src_node_name)
            migration_info.update({'opflexODev_and_L4L7Device_sync' : 'SUCCESS' if sync else 'FAILED'})
            assert sync, ("opflexODev and L4L7Device information are out of sync!")
            migration_info.update({'opflexODev_and_L4L7Device_sync_time' : time_diff})

        is_ready, time_diff = lib.wait_till_node_ready(src_node_name, timeout=NODE_WAIT_TIMEOUT)
        assert is_ready, ("Node %s not Ready after migration", src_node_name)
        migration_info.update({'node_ready_time' : time_diff})

        traffic_resumed, time_diff = scale_helper.check_for_basic_traffic(
            resources, namespaces[0], nodename=src_node_name)
        assert traffic_resumed, ("Traffic not resumed after migration")
        migration_info.update({'traffic_resume_time' : time_diff})

        # Run Traffic test after migration
        try:
            LOG.info("Running Test After %s migration", migration_type)
            scale_helper.check_datapath_connectivity(
                base_fixture, namespaces, resources, nodename=src_node_name)
            migration_info.update({'Traffic_Test_Post_Migration' : "SUCCESS"})
        except Exception as ex:
            LOG.warning("Traffic test after migration failed : %s", ex)
            migration_info.update({'Traffic_Test_Post_Migration' : "FAILED"})
            pass
        if migration_count >= MAX_MIGRATION_COUNT:
            break
    #End of for loop

@pytest.mark.usefixtures("clean_gen_templates")
def vmware_vm_migrate_with_datapath_test(base_fixture, vc, nodes_to_migrate=None, dest_host="", inter_leaf=True, intra_leaf=False):
    """ Test datapath connectivity in Intra & Inter leaf Pair VMWare VM Migrations

    This test performs below steps.
    1. Create resources to test datapath.
    2. Check datapath connectivity before migration
    3. verify_vm_live_migration_test for Intra-Leaf Pair Case
    4. verify_vm_live_migration_test for Inter-Leaf Pair Case
    5. Post migration Delete resources created to test datapath
    6. Post Migration create the resources and check datapath connectivity
    7. Also dump the summary of VM Live Migration test
    """
    result_summary = []
    resources = {}
    namespaces = ["test-vm-ns"]
    migration_info = {"type" : inspect.stack()[1][3]}
    try:
        # Create Test resources
        test_stage = "Pre-Migration_Create_Resources"
        scale_helper.create_datapath_resources_in_parallel(base_fixture, namespaces, resources)
        migration_info.update({test_stage : "SUCCESS"})
        # Run Traffic test before VM Migration
        test_stage = "Pre-Migration_Datapath_test"
        scale_helper.check_datapath_connectivity(base_fixture, namespaces, resources)
        migration_info.update({test_stage : "SUCCESS"})

        test_stage = "VM-Migration"
        # Intra-Leaf Migration
        if intra_leaf:
            LOG.info("Running Intra-Leaf VM Migration Test..")
            verify_vm_live_migration_test(base_fixture, vc, resources, namespaces, result_summary,
                                           nodes_to_migrate=nodes_to_migrate, dest_host=dest_host, inter_leaf=False)
        # Inter-Leaf Migration
        if inter_leaf:
            LOG.info("Running Inter-Leaf VM Migration Test..")
            verify_vm_live_migration_test(base_fixture, vc, resources, namespaces, result_summary,
                                          nodes_to_migrate=nodes_to_migrate, dest_host=dest_host, inter_leaf=True)

        migration_info.update({test_stage : "SUCCESS"})
        # Post Migration Test
        test_stage = "Post-Migration_Delete_Resource"
        scale_helper.delete_datapath_resources(base_fixture, resources)
        migration_info.update({test_stage : "SUCCESS"})
        test_stage = "Post-Migration_Create_Resources_and_Datapath_test"
        scale_helper.create_resources_and_check_datapath_connectivity(
            base_fixture, namespaces)
        migration_info.update({test_stage : "SUCCESS"})
    except Exception as ex:
        migration_info.update({test_stage : "FAILED"})
        LOG.error("VN Migration Test Failed : %s", ex)
        scale_helper.delete_datapath_resources(base_fixture, resources)
        raise
    finally:
        result_summary.append(migration_info)
        test_status = vm_helper.dump_migration_stats(result_summary)
        assert test_status, "VM Migration test Failed!!"

@pytest.mark.skipif(is_multipod() is False, reason="MultiPod Test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_migrate_controller_node(base_fixture, gen_template_name):
    """Migrate the Node where controller exists
        1. Get aci-containers-controller Node and Host
        2. Migrate controller Node to different Host(Inter-Leaf)
    """
    vc = get_vcenter_obj()
    info = update_vm_migraion_global(vc)
    if not info.get('inter_leaf'):
        pytest.skip("Cluster is Not Valid for Inter-Leaf Migration")
    #1. Get aci-containers-controller Node and Host
    controller_node, _ = vc.get_controller_node_and_host()
    if vc.is_valid_node_for_inter_leaf_migration(controller_node) is False:
        pytest.skip("Cluster is Not Valid for controller node Inter-Leaf Migration")
    #2. Migrate controller Node to different Host
    vmware_vm_migrate_with_datapath_test(base_fixture, vc, nodes_to_migrate=[controller_node])

@pytest.mark.skipif(is_multipod() is False, reason="MultiPod Test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_migrate_non_controller_node_from_controller_aci_pod(base_fixture, gen_template_name):
    """Migrate non-controller Node(Any one) from the Host where controller exists 
        1. Get aci-containers-controller Node and Host
        2. Find all other Node running on controller Node Host
        3. Migrate these Node to different Host(Inter-Leaf)
    """
    #1. Get aci-containers-controller Node and Host
    vc = get_vcenter_obj()
    info = update_vm_migraion_global(vc)
    if not info.get('inter_leaf'):
        pytest.skip("Cluster is Not Valid for Inter-Leaf Migration")
    controller_node, controller_host = vc.get_controller_node_and_host()
    #2. Find all other Node running on controller Node Host
    nodes = vc.get_nodes_on_host(controller_host, controller_node)
    if len(nodes) == 0:
        pytest.skip("Valid node not found to migrate")

    #3. Migrate these Node to different Host
    node_list = vc.get_valid_node_for_migration(inter_leaf=True, node_list=nodes)
    if len(node_list) == 0:
        pytest.skip("Valid node not found to migrate")
    LOG.info("Migrating %s", (node_list))
    vmware_vm_migrate_with_datapath_test(base_fixture, vc, nodes_to_migrate=node_list)

@pytest.mark.skipif(is_multipod() is False, reason="MultiPod Test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_migrate_non_controller_node_to_controller_aci_pod(base_fixture, gen_template_name):
    """Migrate non-controller Node to Host where controller exists
        1. Get aci-containers-controller Node and Host
        2. Find all other Nodes not running on controller Node Host
        3. Migrate these Node to controller Host(Inter-Leaf)
    """
    vc = get_vcenter_obj()
    info = update_vm_migraion_global(vc)
    if not info.get('inter_leaf'):
        pytest.skip("Cluster is Not Valid for Inter-Leaf Migration")
    #1. Get aci-containers-controller Node and Host
    _, controller_host = vc.get_controller_node_and_host()
    #2. Find all other Nodes not running on controller Node Host
    node_list = vc.get_valid_node_not_running_on_host(controller_host, inter_leaf=True)
    if len(node_list) == 0:
        pytest.skip("Valid node not found to migrate")
    #3. Migrate these Node to controller Host
    LOG.info("Migrating %s to Dest %s", node_list, controller_host)
    vmware_vm_migrate_with_datapath_test(base_fixture, vc, nodes_to_migrate=node_list, dest_host=controller_host)

@pytest.mark.skipif(is_multipod() is False, reason="MultiPod Test")
@pytest.mark.usefixtures("clean_gen_templates")
def test_migrate_intrapod(base_fixture, gen_template_name):
    """Migrate Node on the host running on same network
    """
    vc = get_vcenter_obj()
    info = update_vm_migraion_global(vc)
    if not info.get('intra_leaf'):
        pytest.skip("Cluster is Not Valid for Intra-Leaf Migration")
    nodes_to_migrate = vc.get_valid_node_for_migration(inter_leaf=False)
    if len(nodes_to_migrate) == 0:
        pytest.skip("No Node found for Intra-Leaf Migration")
    LOG.info("Migrating %s", (nodes_to_migrate))
    vmware_vm_migrate_with_datapath_test(
        base_fixture, vc, nodes_to_migrate=nodes_to_migrate, inter_leaf=False, intra_leaf=True)

@pytest.mark.usefixtures("clean_gen_templates")
def test_inter_and_intra_leaf_pair(base_fixture, gen_template_name):
    """ Test datapath connectivity in Intra & Inter leaf Pair VMWare VM Migrations """
    vc = get_vcenter_obj()
    info = update_vm_migraion_global(vc)
    if not (info.get('intra_leaf') or info.get('inter_leaf')):
        pytest.skip("Cluster is not Valid for Intra or Inter Leaf Migration")
    # Run both Intra and Inter Leaf VM Migration
    vmware_vm_migrate_with_datapath_test(base_fixture, vc, inter_leaf=info.get('inter_leaf'), intra_leaf=info.get('intra_leaf'))
