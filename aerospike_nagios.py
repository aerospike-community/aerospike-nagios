#!/usr/bin/env python
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#

# Copyright 2013-2016 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Description: Nagios script for Aerospike

__author__ = "Aerospike"
__copyright__ = "Copyright 2016 Aerospike"
__version__ = "1.0.0"

import sys
import types
import getopt
import re
import aerospike
import getpass

# Nagios error codes:
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4

RETURN_VAL=STATE_OK

user = None
password = None
arg_host = "127.0.0.1"
arg_port = 3000
arg_value = "statistics"
arg_stat = None
arg_warning = None
arg_critical = None

stat_line = None


###
def usage():
    print "Usage:"
    print " -h host (default 127.0.0.1)"
    print " -p port (default 3000)"
    print " -U user"
    print " -P password"
    print " -s \"statistic\" (Eg: \"free-pct-memory\")"
    print " -n \"namespace\" (Eg: \"namespace/test\")"
    print " -x \"xdr\" (Eg: \"datacenter1\")"
    print " -c \"critical level\" (Eg: \"60\")"
    print " -w \"warning level\" (Eg: \"70\")"
    return
###

###
## Process passed in arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:p:s:n:x:c:w:U:P", ["host=","port=","statistics=","namespace=","xdr=","critical=","warning=","User=","Password="])

    if not opts:
        print "No options supplied."
        print "%s" %args
        usage()
        sys.exit(STATE_UNKNOWN)

## If we don't get in options passed print usage.
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(STATE_UNKNOWN)

for o, a in opts:
    if (o == "-h" or o == "--host"):
        arg_host = a
    if (o == "-p" or o == "--port"):
        arg_port = int(a)
    if (o == "-s" or o == "--statistics"):
        arg_stat = a
    if (o == "-n" or o == "--namespace"):
        arg_value = "namespace/" + a
    if (o == "-x" or o == "--xdr"):
        arg_value = "dc/" + a
    if (o == "-U" or o == "--User"):
        user = a
    if (o == "-p" or o == "--Password"):
        password = a
    if (o == "-c" or o == "--critical"):

        # Do we need to convert to gigabytes
        if re.search(r'\dg$', a, re.IGNORECASE):
            arg_critical = int(a[:-1])
            arg_critical = arg_critical*1024**3

        # Do we need to convert to megabytes
        elif re.search(r'\dm$', a, re.IGNORECASE):
            arg_critical = int(a[:-1])
            arg_critical = arg_critical*1024**2

        elif re.search(r'\D', a):
            print "Illegal character(s) in critical option."
            print "%s" %a
            sys.exit(STATE_UNKNOWN)
        else:
            arg_critical = int(a)

    if (o == "-w" or o == "--warning"):

        # Do we need to convert to gigabytes
        if re.search(r'\dg$', a, re.IGNORECASE):
            arg_warning = int(a[:-1])
            arg_warning = arg_warning*1024**3

        # Do we need to convert to megabytes
        elif re.search(r'\dm$', a, re.IGNORECASE):
            arg_warning = int(a[:-1])
            arg_warning = arg_warning*1024**2

        elif re.search(r'\D', a):
            print "Illegal character(s) in critical option."
            print "%s" %a
            sys.exit(STATE_UNKNOWN)
        else:
            arg_warning = int(a)

# Make sure we have a statistic to look for
if arg_stat is None:
    print "A statistic was not supplied."
    usage()
    sys.exit(STATE_UNKNOWN)

if arg_critical is None:
    print "A critical was not supplied."
    usage()
    sys.exit(STATE_UNKNOWN)

if arg_warning is None:
    print "A warning value was not supplied."
    usage()
    sys.exit(STATE_UNKNOWN)

## /Process passed in arguments
###


#
# MAINLINE
#

if user != None:
    if password == None:
        password = getpass.getpass("Enter Password:")


config = {
        'hosts' : [ (arg_host, arg_port) ]
        }
try:
    client = aerospike.client(config).connect(user,password)
except:
    print("failed to connect to the cluster with", config['hosts'])
    sys.exit(STATE_UNKNOWN)

r = client.info_node(arg_value,(arg_host,arg_port))
client.close()

#r = citrusleaf.citrusleaf_info(arg_host, arg_port, arg_value)

if arg_stat not in r:
    print "%s is not a known statistic." %arg_stat
    sys.exit(STATE_UNKNOWN)

if r == -1:
    print "request to ",arg_host,":",arg_port," returned error."
    sys.exit(STATE_CRITICAL)
    
if r == None:
    print "request to ",arg_host,":",arg_port," returned no data."
    sys.exit(STATE_CRITICAL)

#for arg in arg_stat.split():
#    this_stat_line=""

num_stat = None
for s in r.split(";"):
    if arg_stat + "=" in s:
        num_stat = s.split(arg_stat + "=")[-1]
    if num_stat != None:
        stat_line = 'Aerospike Stats - ' + arg_stat + "=" + num_stat


###
## Comparing the Aerospike value with the warning/critical passed values.
## Default comparison is if the Aerospike value is greater than the warning/critical value.
## Stats with "pct" in them are checked to see if the Aerospike value is less than the warning/critical value.
try:
    num_stat = int(num_stat)
except:
    pass
if "dc_state" in arg_stat:
    if num_stat == 'CLUSTER_UP':
        RETURN_VAL=STATE_OK
    else:
        RETURN_VAL=STATE_CRITICAL
elif "stop-writes" in arg_stat or "system_swapping" in arg_stat:
    if num_stat == 'true':
        RETURN_VAL=STATE_CRITICAL
    elif num_stat == 'false':
        RETURN_VAL=STATE_OK
    else:
        RETURN_VAL=STATE_UNKNOWN
elif "free-pct" in arg_stat:
    if arg_warning != 0: 
        if num_stat < arg_warning:
            RETURN_VAL=STATE_WARNING
    if arg_critical != 0:
        if num_stat < arg_critical:
            RETURN_VAL=STATE_CRITICAL
elif "available_pct" in arg_stat:
    if arg_warning != 0: 
        if num_stat < arg_warning:
            RETURN_VAL=STATE_WARNING
    if arg_critical != 0:
        if num_stat < arg_critical:
            RETURN_VAL=STATE_CRITICAL
elif "cluster_size" in arg_stat:
    if arg_warning != 0: 
        if num_stat < arg_warning:
            RETURN_VAL=STATE_WARNING
    if arg_critical != 0:
        if num_stat < arg_critical:
            RETURN_VAL=STATE_CRITICAL
elif "cluster_integrity" in arg_stat:
    if num_stat == 'true':
        RETURN_VAL=STATE_OK
    elif num_stat == 'false':
        RETURN_VAL=STATE_CRITICAL
    else:
        RETURN_VAL=STATE_UNKNOWN
elif "xdr-uptime" in arg_stat:
    if arg_warning != 0:
        if num_stat < arg_warning:
            RETURN_VAL=STATE_WARNING
    if arg_critical != 0:
        if num_stat < arg_critical:
            RETURN_VAL=STATE_CRITICAL
    else:
        RETURN_VAL=STATE_OK
else:
    if arg_warning != 0: 
        if num_stat > arg_warning:
            RETURN_VAL=STATE_WARNING
    if arg_critical != 0:
        if num_stat > arg_critical:
            RETURN_VAL=STATE_CRITICAL

# Append perf data if data is numeric
append_perf=True
try:
    float(num_stat)
except:
    append_perf=False

## /Comparison
###
        
###
## Print stat information and the return code for Nagios
###

if stat_line != "":
    if append_perf:
        print '%s|%s=%d;%d;%d' % (stat_line,arg_stat,num_stat,arg_warning,arg_critical) 
    else:
        print '%s' % (stat_line)
    sys.exit(RETURN_VAL)

## /Print
###
