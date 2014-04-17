#!/usr/bin/env python

import pynag  # Dependency 0.8.5
import lib.acitrusleaf as cf
import lib.util as util
util.logging = False
import pickle
import tempfile
import os
import socket
from time import time
from lib.filelock import FileLock
from pprint import pprint
from pynag.Plugins import PluginHelper, ok, warning, critical, UNKNOWN

def get_data(helper):
    host_group = helper.options.host_group
    temppath = "%s/%s"%(tempfile.gettempdir()
                        , 'asnagios')

    # Create the path if it does not exist
    try:
        os.makedirs(temppath)
    except OSError:
        pass

    temppath = "%s/%s"%(temppath, host_group)
    lockpath = "%s.lock"%(temppath)
    lock = FileLock(lockpath, timeout=50)
    try:
        with lock:
            try:
                with open(temppath, 'r') as f:
                    data = pickle.load(f)
            except:
                data = []

            # data is stale, lets get some new data
            if not data or data[0]['time_collected'] + 10 < time():
                new_data = {}
                hosts = cf.find_hosts(helper.options.host
                                      , helper.options.port)
                hosts = sorted(hosts)
                for (host_ip, host_port) in hosts:
                    stats = cf.info_statistics(host_ip, host_port)
                    namespace_stats = cf.info_namespace_stats(host_ip
                                                              , host_port)
                    host_key = "%s:%s"%(host_ip, host_port)
                    new_data[host_key] = {'statistics' : stats
                                          , 'namespace' : namespace_stats
                                          , 'xdr' : None}
                    try:
                        xdr_port = int(helper.options.xdr_port)
                        xdr_stats = cf.info_statistics(host_ip, xdr_port)
                        new_data['xdr'] = xdr_stats
                    except:
                        pass  # no xdr
                new_data['time_collected'] = time()

                data.insert(0, new_data)
                if len(data) > 2:
                    data = data[0:2]
                with open(temppath, 'w') as f:
                    pickle.dump(data, f)
    except FileLock.FileLockException:
        # If another program hangs the lock, it will be required form an op to
        # manually purge the file.
        exit(-1)
    return data

aggregation_functions = set(['sum', 'max', 'min'])

def convert_data(helper, data):
    value_type = helper.options.value_type

    if value_type == 'number':
        func = float
    elif value_type == 'boolean':
        func = lambda v: False if v == 'false' or v == 'no' or v == '0' else True
    return [[func(datum) for datum in data_list] for data_list in data]


def get_value(helper):
    data = get_data(helper)
    statistic_type = helper.options.statistic_type
    statistic = helper.options.statistic
    value_type = helper.options.value_type
    delta = helper.options.delta
    aggregation = helper.options.aggregation

    if delta == 'y':
        stat_data = data
    else:
        stat_data = data[0:1]

    for datum in stat_data:
        del(datum['time_collected'])

    if aggregation not in aggregation_functions:
        host_key = "%s:%s"%(socket.gethostbyname(helper.options.host)
                            , helper.options.port)
        stat_data = [[value[host_key][statistic_type][statistic]] for value in stat_data]
        stat_data = convert_data(helper, stat_data)
        agg_func = lambda v: v[0]
    else:
        stat_data = [[value[statistic_type][statistic] for value in hosts.itervalues()] for hosts in stat_data]
        stat_data = convert_data(helper, stat_data)
        if aggregation == 'min':
            agg_func = min
        elif aggregation == 'max':
            agg_func = max
        elif aggregation == 'sum':
            agg_func = sum

    stat_data = [agg_func(data_list) for data_list in stat_data]
    
    if delta == 'y':
        if len(stat_data) > 1:
            result = stat_data[0] - stat_data[1]
        else:
            result = None
            pass
    else:
        result = stat_data[0]

    return result


def summaraize(helper, value):
    aggregation = helper.options.aggregation
    if aggregation not in aggregation_functions:
        aggregation = False
    statistic_type = helper.options.statistic_type
    statistic = helper.options.statistic
    delta = helper.options.delta
    host_group = helper.options.host_group
    host = "%s:%s"%(helper.options.host
                    , helper.options.port)

    stat_name = "%s.%s"%(statistic_type, statistic)
    if aggregation:
        stat_name = "%s.%s(%s)"%(host_group, aggregation, stat_name)
    else:
        stat_name = "%s.%s.%s"%(host_group, host, stat_name)

    if delta == 'y':
        stat_name = "delta(%s)"%(stat_name)

    helper.add_metric(label=stat_name, value=value)
    helper.add_summary("%s=%s"%(stat_name, value))


def checker(helper):
    if helper.options.value_type == 'boolean':
        convert_metric = lambda metric: False if not metric or metric == 'n' else True
    else:
        convert_metric = lambda metric: False if not metric or metric == 'n' else True

    high_critical = convert_metric(helper.options.high_critical)
    low_critical = convert_metric(helper.options.low_critical)
    high_warning = convert_metric(helper.options.high_warning)
    low_warning = convert_metric(helper.options.low_warning)

    value = get_value(helper)

    summaraize(helper, value)

    helper.status(ok)

    if value == None:
        helper.exit()

    if (low_warning is not False and value <= low_warning):
        helper.status(warning)
    if (high_warning is not False and value >= high_warning):
        helper.status(warning)
    if (low_critical is not False and value <= low_critical):
        helper.status(critical)
    if (high_critical is not False and value >= high_critical):
        helper.status(critical)

    helper.exit()


def main():
    helper = PluginHelper()
    parser = helper.parser

    parser.add_option('-H'
                      , '--host'
                      , help='Host to connect to'
                      , dest='host')

    parser.add_option('-P'
                      , '--port'
                      , help="Host's port to connect to"
                      , dest='port')

    parser.add_option('-X'
                      , '--xdr-port'
                      , help="Host's xdr port to connect to"
                      , dest='xdr_port')

    parser.add_option('-G'
                      , '--host-group'
                      , help='Host group calling'
                      , dest='host_group')
    
    parser.add_option('-T'
                      , '--type'
                      , help='Type of stat being requests: statistics, ' + \
                             'namespace, or xdr'
                      , dest='statistic_type')
    
    parser.add_option('-S'
                      , '--statistic'
                      , help='Name of statistic we are gathering'
                      , dest='statistic')
    
    parser.add_option('-V'
                      , '--value-type'
                      , help='Type of value returned by stat: number or boolean'
                      , dest='value_type')
    
    parser.add_option('-D'
                      , '--delta'
                      , help='if "y" then amount changed since last read else ' + \
                      'use current value.'
                      , dest='delta')
    
    parser.add_option('-A'
                      , '--aggregation'
                      , help='Aggregation to be used with reporting. ' + \
                      'Options: none, min, max, sum'
                      , dest='aggregation')
    
    parser.add_option('-C'
                      , '--high-critical'
                      , help='Yeild critical status if stat value is greater equal'
                      , dest='high_critical')
    
    parser.add_option('-c'
                      , '--low-critical'
                      , help='Yeild critical status if stat value is less equal'
                      , dest='low_critical')
    
    parser.add_option('-W'
                      , '--high-warning'
                      , help='Yeild warning status if stat value is greater equal'
                      , dest='high_warning')
    
    parser.add_option('-w'
                      , '--low-warning'
                      , help='Yeild warning status if stat value is less equal'
                      , dest='low_warning')
    
    parser.add_option('-N'
                      , '--namespace'
                      , help='Name of the namespace to get stat from'
                      , dest='namespace')
    
    helper.parse_arguments()
    checker(helper)
    

if __name__ == '__main__':
    main()
