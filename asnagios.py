#!/usr/bin/env python

import pynag  # Dependency 0.8.5
import pynag.Model
import yaml  # Dependency: 3.11
import lib.acitrusleaf as cf
import lib.util as util
import time
import os
import sys
import glob
import socket
from pprint import pprint

class AsNagios(object):
    """
    Class used to bootstrap a nagios .cfg file when provided a host in an
    Aerospike cluster.
    """
    @classmethod
    def _parse_config(cls, config_path):
        f = file(config_path, 'r')
        full_config = yaml.load(f)
        # Set cluster defaults
        cluster_configs = full_config['clusters']
        for config in cluster_configs:
            if 'seed-port' not in config:
                config['seed-port'] = 3000
            if 'alumni' not in config:
                config['alumni'] = False 
            if 'xdr-port' not in config:
                config['xdr-port'] = False

        # Set service defaults
        service_configs = full_config['services']
        for config in service_configs:
            if 'description' not in config or not config['description']:
                config['description'] = config['name']
            if 'value-type' not in config:
                config['value-type'] = 'number'
            if 'aggregation' not in config:
                config['aggregation'] = 'none'
            if 'delta' not in config:
                config['delta'] = False
            if 'trend' not in config:
                config['trend'] = True  # TODO: NOT IMPLEMENTED

            if 'low-critical' not in config:
                config['low-critical'] = 'n'
            if 'low-warning' not in config:
                config['low-warning'] = 'n'
            if 'high-warning' not in config:
                config['high-warning'] = 'n'
            if 'high-critical' not in config:
                config['high-critical'] = 'n'

            if config['low-critical'] is True:
                config['low-critical'] = 'y'
            if config['high-critical'] is True:
                config['high-critical'] = 'y'
            if config['low-warning'] is True:
                config['low-warning'] = 'y'
            if config['high-warning'] is True:
                config['high-warning'] = 'y'

            if 'namespace' not in config:
                config['namespace'] = 'all'  # TODO: NOT IMPLEMENTED
        return full_config

    @classmethod
    def _findNodes(cls, cluster_config):
        hosts = cf.find_hosts(cluster_config['seed-host']
                              , cluster_config['seed-port']
                              , cluster_config['alumni'])
        named_hosts = {}
        for host in hosts:
            name = socket.gethostbyaddr(host[0])[0]
            named_hosts[name] = host

        return named_hosts

    @classmethod
    def _findNamespaces(cls, cluster_config):
        return cf.find_namespaces(cluster_config['seed-host']
                                  , cluster_config['seed-port'])

    @classmethod
    def _createFile(cls, output_path, file_name):
        path = "%s/%s.cfg"%(output_path, file_name)
        try:
            os.remove(path)
        except OSError:
            pass  # File does not exist.. ok

        try:
            os.makedirs(os.path.dirname(path))
        except OSError:
            pass
        open(path, 'a').close()

        return path

    @classmethod
    def _createServiceFile(cls, output_path):
        name = 'aerospike_services'
        return cls._createFile(output_path, name)

    @classmethod
    def _createClusterFile(cls, cluster_config, output_path):
        name = cluster_config['name']
        return cls._createFile(output_path, name)

    @classmethod
    def _bootstrapHostTemplate(cls, output_path):
        pass
        # TODO: Create a host template

    @classmethod
    def _bootstrapHosts(cls, hosts, cluster_config, output_path):
        pynag.Model.cfg_file = output_path
        for (host_name, (host_address, _)) in hosts.iteritems():
            h = pynag.Model.Host()
            h.use = 'linux-server'
            h.host_name = host_name
            h.alias = host_name
            h.address = host_address
            h.save(filename=output_path)

    @classmethod
    def _bootstrapHostGroup(cls, hosts, cluster_config, output_path):
        members = [host for host in hosts.keys()]
        hg = pynag.Model.Hostgroup()
        hg.hostgroup_name = cluster_config['name']
        hg.members = ','.join(members)
        hg.save(filename=output_path)

        return cluster_config['name']

    @classmethod
    def _bootstrapServiceTemplate(cls):
        pass

    @classmethod
    def _createService(cls, name, host_groups, service_config, output_path):
        s = pynag.Model.Service()
        s.hostgroup_name = ','.join(host_groups)
        s.use = 'generic-service'
        s.service_description = name
        # TODO: this cannot support different nodes using different service/xdr ports :(
        s.check_command = "check_aerospike!%s!%s!%s!%s!%s!%s!%s!%s!%s!%s!%s!%s"%(
            3000  # TODO: Should be port defined in cluster config
            , 'n'  # TODO: Should be xdr port defined in cluster config
            , service_config['type']
            , service_config['statistic']
            , service_config['value-type']
            , 'y' if service_config['delta'] else 'n'
            , service_config['aggregation']
            , service_config['high-critical']
            , service_config['low-critical']
            , service_config['high-warning']
            , service_config['low-warning']
            , service_config['namespace'])
            
        s.notification_enabled = 1
        s.save(filename=output_path)

    @classmethod
    def _bootstrapCommand(cls, output_path):
        c = pynag.Model.Command()
        c.command_name = 'check_aerospike'
        c.command_line = '/usr/bin/python $USER1$/check_aerospike.py -H "$HOSTADDRESS$" -G "$HOSTGROUPNAME$" -P "$ARG1$" -X "$ARG2$" -T "$ARG3$" -S "$ARG4$" -V "$ARG5$" -D "$ARG6$" -A "$ARG7$" -C "$ARG8$" -c "$ARG9$" -W "$ARG10$" -w "$ARG11$" -N "$ARG12$"'
        c.save(filename=output_path)

    @classmethod
    def _bootstrapService(cls, host_groups, namespaces, service_config, output_path):
        if service_config['type'] == 'namespace':
            namespace = service_config['namespace']
            for (group_name, namespace_list) in namespaces.iteritems():
                if namespace == 'all' or namespace in namespace_list:
                    for namespace in namespace_list:
                        name = "%s - %s"%(namespace, service_config['name'])
                        cls._createService(name, [group_name], service_config, output_path)
        else:
            name = service_config['name']
            cls._createService(name, host_groups, service_config, output_path)

    @classmethod
    def bootstrap(cls, config_path, output_path):
        config = cls._parse_config(config_path)
        cluster_configs = config['clusters']
        service_configs = config['services']
        # cls._bootstrapHostTemplate(output_path)
        host_groups = []
        namespaces = {}
        for cluster_config in cluster_configs:
            path = cls._createClusterFile(cluster_config, output_path)
            hosts = cls._findNodes(cluster_config)
            ns = cls._findNamespaces(cluster_config)
            cls._bootstrapHosts(hosts, cluster_config, path)
            host_group = cls._bootstrapHostGroup(hosts, cluster_config, path)
            host_groups.append(host_group)
            namespaces[host_group] = ns
                
        # cls._bootstrapServiceTemplate(output_path)
        path = cls._createServiceFile(output_path)
        cls._bootstrapCommand(path)
        for service_config in service_configs:
            cls._bootstrapService(host_groups, namespaces, service_config, path)


def main():
    from optparse import OptionParser

    description = ""
    parser = OptionParser(description=description)

    parser.add_option('-o'
                      , '--output-path'
                      , dest='output_path'
                      , type='string'
                      , default='./aerospike/'
                      , help='Path for storing resulting cfg files ' + \
                             '[default: %default]')

    parser.add_option('-c'
                      , '--config-path'
                      , dest='config_path'
                      , type='string'
                      , default='./config.yml'
                      , help='Location of cluster config file or directory ' + \
                             'containing config files. [required]')

    (options, _) = parser.parse_args()
    config_path = os.path.abspath(options.config_path)
    output_path = os.path.abspath(options.output_path)

    if os.path.isdir(config_path):
        config_list = glob.glob("%s/*.yml"%(config_path))
    else:
        config_list = [config_path]

    if not os.path.isdir(output_path):
        if os.path.exists(output_path):
            raise TypeError("Output path must be a directory")
        else:
            try:
                os.makedirs(os.path.dirname(output_path))            
            except OSError:
                pass

    for config in config_list:
        AsNagios.bootstrap(config, output_path)

if __name__ == '__main__':
    main()
