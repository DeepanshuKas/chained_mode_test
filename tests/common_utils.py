import yaml
import re
from tests.input.cfg import APIC_PROVISION_FILE
from kubernetes import client, config
from acc_pyutils.utils import execute

def get_apic_provision_input(provision_file):
    with open(provision_file, 'r') as prov_file:
        apic_prov = yaml.load(prov_file, Loader=yaml.SafeLoader)
    return apic_prov

def check_chained_mode():
    """Check CNI in chained mode

    1. Get acc-provision input file.
    2. If 'secondary_interface_chaining' or 'primary_interface_chaining' is 'true' under section
       'chained_cni_config' then, it's chained CNI mode.
    """
    apic_provision = get_apic_provision_input(APIC_PROVISION_FILE)
    if apic_provision.get("chained_cni_config") and (
        apic_provision["chained_cni_config"].get("secondary_interface_chaining") or apic_provision[
            "chained_cni_config"].get("primary_interface_chaining")):
        return True
    return False

def get_oc_version(cmd):
    cmd_list = cmd.split(" ")
    version = execute(cmd_list)
    server_version_match = re.search(r'Server Version: (\d+\.\d+\.\d+)', version.decode('utf-8'))
    if server_version_match:
        server_version = server_version_match.group(1)
        return server_version
    return None

def get_kubernetes_version():
    try:
        config.load_kube_config()
        api_instance = client.VersionApi()
        version_info = api_instance.get_code()
        kubernetes_version_str = version_info.git_version
        kubernetes_version = kubernetes_version_str[1:]
        return kubernetes_version
    except Exception as e:
        print(f"Error: {e}")
