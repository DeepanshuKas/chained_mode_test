import os

import yaml

from acc_pyutils.utils import Server

INPUT_DIR = os.path.abspath('tests/input')


class ServerUtils:
    def __init__(self):
        self.server_objects = self.get_server_objects()

    def get_server_objects(self):
        server_obj = dict()
        node_info = self.load_nodes_information()
        for node in (node_info['manager_nodes']
                     + node_info.get('worker_nodes', [])
                     + node_info.get('external_router_nodes', [])):
            server_obj[node['hostname']] = self.create_server_obj(node)
        return server_obj

    def get_k8_cluster_objects(self):
        server_obj = dict()
        node_info = self.load_nodes_information()
        for node in (node_info['manager_nodes']
                     + node_info.get('worker_nodes', [])):
            server_obj[node['hostname']] = self.create_server_obj(node)
        return server_obj

    def get_server_object_by_name(self, name):
        for srv_name, obj in self.server_objects.items():
            if srv_name == name:
                return obj
        # Server not found, refresh server_objects
        server_obj = self.get_server_objects()
        for srv_name, obj in server_obj.items():
            if srv_name == name:
                self.server_objects[srv_name] = obj
                return obj
        raise Exception('Server - %s not found.' % name)

    def get_server_object_by_ip(self, ip):
        for _, obj in self.server_objects.items():
            if obj.__dict__['host_ip'] == ip:
                return obj
        raise Exception('Server with IP - %s not found.' % ip)

    def get_external_router(self):
        router_name = self._get_remote_router_hostname()
        return self.get_server_object_by_name(router_name)

    def _get_remote_router_hostname(self):
        nodes_info = self.load_nodes_information()
        for node in nodes_info.get('external_router_nodes', []):
            return node['hostname']
        raise Exception('External router configuration not provided.')

    def load_nodes_information(self):
        node_info_file = INPUT_DIR + '/nodes_info.yaml'
        with open(node_info_file, 'r') as node_file:
            nodes_info = yaml.safe_load(node_file)
        return nodes_info

    @staticmethod
    def create_server_obj(server_info):
        return Server(hostname=server_info['hostname'],
                      host_ip=server_info['host_ip'],
                      username=server_info['username'],
                      password=server_info['password'],
                      key_filename=server_info['key_filename'],
                      port=server_info.get('port', 22))
