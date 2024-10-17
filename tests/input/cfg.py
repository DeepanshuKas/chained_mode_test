SNAT_FILE_PATH = '/var/lib/opflex-agent-ovs/snats/'
EP_FILE_PATH = '/var/lib/opflex-agent-ovs/endpoints/'
SVC_FILE_PATH = '/var/lib/opflex-agent-ovs/services/'
NETPOL_FILE_PATH = '/var/lib/opflex-agent-ovs/netpols/'

# File name with 'null-mac' substring will be searched in EP_FILE_PATH on all
# nodes.
NULL_MAC_FILE_SEARCH_STR = 'null-mac'

# If REMOTE_ROUTER is set True, then framework will consider test running node
# different from external router. User must pass external router info in
# 'external_router_nodes' section of './nodes_info.yaml' input file.
#
# All the below information EXTERNAL_ROUTER_INTERFACE, EXTERNAL_ROUTER_IP,
# EXTERNAL_LISTENING_PORT, EXTERNAL_IP_POOL will be considered part of
# external router.
#
# By default, REMOTE_ROUTER is set to False, in which test framework considers
# test running node as external router.
#
# Important - screen needs to be installed on REMOTE_ROUTER irrespective of
# True or False, otherwise tests will fail. This is a temporary limitation.
#
REMOTE_ROUTER = False
EXTERNAL_ROUTER_INTERFACE = '1XXXX'
EXTERNAL_ROUTER_IP = 'P.Q.R.S'
EXTERNAL_LISTENING_PORT = ''
EXTERNAL_IP_POOL = ['A.A.B.B', 'C.C.D.D', 'X.X.Y.Y']

PYTHON_EXEC = 'python'
# For python 3.x version, set to 3.
HTTP_SERVER_VERSION = 2

# If sets to True, tests will clean the resources which got created. If False,
# resources will be left as it is only to get cleaned manually. Very useful for
# developers.
CLEAN_IF_FAIL = True

# If sets to True, pkt generated during traffic validation are captured on
# server side using tcpdump.
PKT_CAPTURE_ENABLED = False

CRD_NAMESPACE = 'aci-containers-system'
KUBE_SYSTEM = 'kube-system'
ACI_PREFIX = 'aci-containers'
ACI_CHAINED_PREFIX = 'netop'

APIC_PROVISION_FILE = ""
APIC_VALIDATION = True

# APIC creds
APIC_USERNAME = ""
APIC_PASSWORD = ""

# Set the network timeout to seconds for wget
WGET_CONNECTION_TIMEOUT = 30
WGET_RETIRES = 2
# Maximum waiting time for epg endpoint to changed its compute
# life cycle into learned,vmm state
ENDPOINT_WAIT_TIME = 120


# SNAT stress testing
POLICY_COUNT = 50
ITERATIONS = 10
SLEEP_BETWEEN_ITERATIONS = 30 #seconds
SNAT_STRESS_TRAFFIC_VALIDATION= True # Option to validate traffic
REPLICA_COUNT = 2

# [ acc provision operator config ]
# specify the aci cni operator version for CNI upgrade.
ACI_CNI_OPERATOR_VERSION = ""
# specify the aci host agent image version that you want to update to.
ACI_CONTAINERS_HOST_VERSION = ""
# If sets to True, accprovisioninput CR config will restore
# to original state after successful update/upgrade.
REVERT_UPDATE = True
# Set it to True to enable resource profiling (CPU/Memory usages)
RESOURCE_PROFILING_ENABLE = True

# [Reconciliation object count test config]
# specify number of namespace count
NAMESPACE_COUNT = 5

OPENSHIFT_ADMIN_OS_PROJECT_NAME = "admin"
OPENSHIFT_BASE_DOMAIN = "noiro.local"

# Collect pprof profiling data for stress tests
COLLECT_PROFILING_DATA = False

# Use crictl command to pull images on nodes
USE_CRICTL_FOR_IMAGE_PULL = False

# Name of physical interface associated with MACVLAN
MACVLAN_ASSOCIATED_INTERFACE = "bond1"

# Run Multipod test
MULTIPOD_TEST = False

# Vcenter config used for vmware VM migration
VC_CONFIG = {
        'IP' :'<VC IP>',
        'USER' : '<VC username>',
        'PASSWD' : '<VC password>',
        # Host Deatils Optional default automatically calculated
        'HOST_DETAILS' : {'leaf-1' : [{'host' : '<host1_name>', 'ds' : '<ds_name>'},
                                      {'host' : '<host2_name>', 'ds' : '<ds_name>'}],
                          'leaf-2' : [{'host' : '<host3_name>', 'ds' : '<ds_name>'}]},
        #'FOLDER' : '<Folder name>', # Optional default system_id or scan all VMs to get Folder name if not found
}

# HPP policy config used for hpp policy programming time test
HPP_POLICY_CONFIG = {
        'RESOURCE_SET_COUNT' : 100, #Each set contains a namespace, ngnix deployment & snatpolicy
        'REPLICAS' : 2 #Number of replicas for a deploy
}

# Timeout for node to be ready after reboot
NODE_READY_AFTER_REBOOT_TIMEOUT = 300

#Container runtime password podman
PODMAN_PASSWORD = ""

#VM Migrationin configuration
MAX_MIGRATION_COUNT = 1
NODE_WAIT_TIMEOUT = 1200
TRAFFIC_RESUME_TIMEOUT = 1200
VM_MIGRATION_TIMEOUT = 3600
#For debugging purpose
NODE_LIST_TO_MIGRATE = []

