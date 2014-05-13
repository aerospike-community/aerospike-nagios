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
from pprint import pprint
from lib.filelock import FileLock
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
            query_interval = int(helper.options.query_interval)
            query_retention = int(helper.options.query_retention)
            if not data or data[0]['time_collected'] + query_interval < time():
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
                if len(data) > query_retention:
                    data = data[0:query_retention]
                with open(temppath, 'w') as f:
                    pickle.dump(data, f)
    except FileLock.FileLockException:
        # If another program hangs the lock, it will be required form an op to
        # manually purge the file.
        exit(-1)
    return data

aggregation_functions = {'sum':sum, 'max':max, 'min':min}

def convert_data(helper, data):
    value_type = helper.options.value_type

    if value_type == 'number':
        func = float
    elif value_type == 'boolean':
        func = lambda v: False if v == 'false' or v == 'no' or v == '0' else True
    return [[func(datum) for datum in data_list] for data_list in data]


def compute_delta(stat_data):
    """
    Change between the the most recent min value and most recent max value.
    [5,4] => 1 
    [4,5] => -1
    [5,4,3] => 2
    [3,4,5] => -2
    [3,5,2] => 3
    [3,2,5] => -3
    [3,2,5,2] => -3
    [3,5,2,5] => 3
    """
    
    min_value = min(stat_data)
    max_value = max(stat_data)
    min_index = stat_data.index(min_value)
    max_index = stat_data.index(max_value)

    result = min_value - max_value if min_index < max_index else max_value - min_value
    
    return result

def get_value(helper):
    data = get_data(helper)
    statistic_type = helper.options.statistic_type
    statistic = helper.options.statistic
    value_type = helper.options.value_type
    delta = helper.options.delta
    aggregation = helper.options.aggregation
    namespace = helper.options.namespace

    if delta == 'y':
        stat_data = data
    else:
        stat_data = data[0:1]

    for datum in stat_data:
        del(datum['time_collected'])

    if aggregation not in aggregation_functions:
        host_key = "%s:%s"%(socket.gethostbyname(helper.options.host)
                            , helper.options.port)
        if statistic_type != 'namespace':
            stat_data = [[value[host_key][statistic_type][statistic]]
                         for value in stat_data]
        else:
            stat_data = [[value[host_key][statistic_type][namespace][statistic]]
                         for value in stat_data]
            
        stat_data = convert_data(helper, stat_data)
        agg_func = lambda v: v[0]
    else:
        if statistic_type != 'namespace':
            stat_data = [[value[statistic_type][statistic]
                          for value in hosts.itervalues()] for hosts in stat_data]
        else:
            stat_data = [[value[statistic_type][namespace][statistic]
                          for value in hosts.itervalues()] for hosts in stat_data]
            
        stat_data = convert_data(helper, stat_data)
        agg_func = aggregation_functions[aggregation]

    stat_data = [agg_func(data_list) for data_list in stat_data]
    if delta == 'y':
        if len(stat_data) > 1:
            result = compute_delta(stat_data)
        else:
            result = None
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

    # TODO: Use stat name define by config.yml
    #       Or use this nameing algorithm.
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
        convert_metric = lambda metric: None if not metric or metric == 'n' else False if metric == 'false' or metric == 'no' or metric == '0' else True
    else:
        convert_metric = lambda metric: None if not metric or metric == 'n' else float(metric)

    high_critical = convert_metric(helper.options.high_critical)
    low_critical = convert_metric(helper.options.low_critical)
    high_warning = convert_metric(helper.options.high_warning)
    low_warning = convert_metric(helper.options.low_warning)

    value = get_value(helper)

    summaraize(helper, value)

    helper.status(ok)

    if value == None:
        helper.exit()

    if (low_warning is not None and value <= low_warning):
        helper.status(warning)
    if (high_warning is not None and value >= high_warning):
        helper.status(warning)
    if (low_critical is not None and value <= low_critical):
        helper.status(critical)
    if (high_critical is not None and value >= high_critical):
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
    
    parser.add_option('-I'
                      , '--query-interval'
                      , help='How often in seconds should the stat be queried'
                      , dest='query_interval')
    
    parser.add_option('-R'
                      , '--query-retention'
                      , help='How many captures will the plugin retain'
                      , dest='query_retention')
    
    helper.parse_arguments()
    checker(helper)
    

if __name__ == '__main__':
    main()
