
#kubeconfig file location(i.e absolute path) for cluster 2
KUBECONFIG_CLUSTER_2 = ""

APIC_PROVISION_FILE_CLUSTER_2 = ''
# [Below input required for shared service case 2]
# Below vm's details required for shared service test-2 i.e
# Access ext service running in common tenant from VM in a different vrf/tenant
# VM should be launched in kube-nodes epg of second cluster with wget installed
CLUSTER2_TEST2_VM_IP = 'P.Q.R.S'
CLUSTER2_TEST2_VM_USERNAME = ''
CLUSTER2_TEST2_VM_PASSWORD = ''

# set ROUTE_ADD_REQUIRED as True if static route
# for service IP needs to be added on CLUSTER2_TEST2_VM_IP
ROUTE_ADD_REQUIRED = False
# external service subnet of cluster 1
EXT_SERVICE_SUBNET = 'P.Q.R.S/T'
# node network gateway of cluster 2
NODE_NET_GW = 'P.Q.R.S'
# node network interface of cluster 2
NODE_NET_INF = ''


# [Below input required for shared service case 3]
# L3out, OutsideEPG and ext subnet details for second cluster 2
# this is required for shared service case 3 test i.e
# Access ext service running in common tenant from an
# external router of different vrf/tenant
EXT_SUBNET_NAME_CLUSTER_2 = ''
# ip of the external subnet
EXT_SUBNET_IP_CLUSTER_2 = 'P.Q.R.S/X'

CLUSTER2_EXT_ROUTER_NODE_IP = 'P.Q.R.S'
CLUSTER2_EXT_ROUTER_NODE_USERNAME = ''
CLUSTER2_EXT_ROUTER_NODE_PASSWORD = ''
CLUSTER2_L3OUT_INTERFACE_IP = ''
