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
__version__ = "1.3.1"

import sys
import yaml
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


schema_path = '/opt/aerospike/bin/aerospike_schema.yaml'
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
    print " -l \"latency\" (Options: reads, writes, writes_reply, proxy)"
    print " -c \"critical level\" (Eg: \"60\")"
    print " -w \"warning level\" (Eg: \"70\")"
    return
###

###
## Process passed in arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:p:s:n:x:l:c:w:U:P", ["host=","port=","statistics=","namespace=","xdr=","latency=","critical=","warning=","User=","Password="])

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
    if (o == "-l" or o == "--latency"):
        arg_value = "latency:hist=" + a
    if (o == "-U" or o == "--User"):
        user = a
    if (o == "-p" or o == "--Password"):
        password = a
    if (o == "-c" or o == "--critical"):
        arg_critical = a
    if (o == "-w" or o == "--warning"):
        arg_warning = a

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


# Takes a range in the format of [@]start:end
# Negative values also ok
# See Nagios guidelines: https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT
NAGIOS_OUTER_THRESHOLD=0        # alert if ouside range of { start ... end }        eg: 10:20
NAGIOS_INNER_THRESHOLD=1        # alert if inside range of { start ... end }        eg: @10:20

def parseRange(myRange):
    # check syntax
    match = re.match("^@?(-?\d+|~)$|^@?(-?\d*|~):-?\d+$",myRange)
    if not match:
        print "Threshold format is incorrect. The format is: [@]start:end. Entered value: %s"%(myRange)
        sys.exit(STATE_UNKNOWN)
    # theshold mode
    mode = NAGIOS_OUTER_THRESHOLD
    if myRange.startswith("@"):
        myRange = myRange.strip("@")
        mode=NAGIOS_INNER_THRESHOLD
    # grab start/end values. Start is optional
    values = myRange.split(":")
    end = values[-1]
    if end == '':
        end = 0
    try:
        start = float(values[-2])
    except:
        start = 0
    if start != "~":
        if float(start) > float(end):
            print "Error: start threshold is greater than the end threshold: %s"%(myRange)
            sys.exit(STATE_UNKNOWN)
    return { "start": start, "end" : int(end), "mode" : mode } 

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

value = None
latency_time = ["1ms", "8ms", "64ms"]
if arg_stat in latency_time:
    s = r.split(";")
    n = 1
    for t in latency_time:
        n += 1
        if t == arg_stat:
            value = s[1].split(",")[n]
            arg_stat = ">" + arg_stat
        if value != None:
            stat_line = 'Aerospike Stats - ' + arg_value + ": " + arg_stat + "=" + value
else:
    for s in r.split()[-1].split(";"):	# remove leading category, then split k=v tuples
        if s.startswith(arg_stat + "="):
            value = s.split(arg_stat + "=")[-1]
        if value != None:
            stat_line = 'Aerospike Stats - ' + arg_stat + "=" + value

#
# Load schema file
#
with open(schema_path) as schema_file:
    schema = yaml.load(schema_file)


#
# Find  unit of measurement for the statstic
#

uom = ''

for category in schema:
    if "operations" in schema[category] and arg_stat in schema[category]["operations"]:
        uom = 'c'
        break
    if "bytes" in schema[category] and arg_stat in schema[category]["bytes"]:
        uom = 'B'
        break
    if "percent" in schema[category] and arg_stat in schema[category]["percent"]:
        uom = '%'
        break


###
## Comparing the Aerospike value with the warning/critical passed values.
## Default comparison is if the Aerospike value is greater than the warning/critical value.
## Stats with "pct" in them are checked to see if the Aerospike value is less than the warning/critical value.


#
# Parse warn/crit ranges

RETURN_VAL=STATE_OK
append_perf=False
if "dc_state" in arg_stat:
    if value != 'CLUSTER_UP':
        RETURN_VAL=STATE_CRITICAL
elif arg_stat in ["stop-writes","system_swapping"]:
    if value == 'true':
        RETURN_VAL=STATE_CRITICAL
elif arg_stat in ["cluster_integrity"]:
    if value == 'false':
        RETURN_VAL=STATE_CRITICAL
else:
    # Append perfdata iff metric value is numeric
    try:
        value = float(value)
        append_perf=True
    except:
        pass
    # Warning threshold first
    if arg_warning != "0":
        warn = parseRange(arg_warning)
        if warn["mode"] == NAGIOS_OUTER_THRESHOLD:
            if warn["start"] == "~":
                if value >=  warn["end"]:
                    RETURN_VAL=STATE_WARNING
            elif value < warn["start"] or value >= warn["end"]:
                    RETURN_VAL=STATE_WARNING
        else: # NAGIOS_INNER_THRESHOLD
            if warn["start"] == "~":
                if value <  warn["end"]:
                    RETURN_VAL=STATE_WARNING
            elif value > warn["start"] and value < warn["end"]:
                    RETURN_VAL=STATE_WARNING
    # Critical threshold override warning threshold
    if arg_critical != "0":
        crit = parseRange(arg_critical)
        if crit["mode"] == NAGIOS_OUTER_THRESHOLD:
            if crit["start"] == "~":
                if value >=  crit["end"]:
                    RETURN_VAL=STATE_CRITICAL
            elif value < crit["start"] or value >= crit["end"]:
                    RETURN_VAL=STATE_CRITICAL
        else: # NAGIOS_INNER_THRESHOLD
            if crit["start"] == "~":
                if value <  crit["end"]:
                    RETURN_VAL=STATE_CRITICAL
            elif value > crit["start"] and value < crit["end"]:
                    RETURN_VAL=STATE_CRITICAL



# Append Unit of measurement
perf_stat = str(value)+uom
        
###
## Print stat information and the return code for Nagios
##

if stat_line != "":
    if append_perf:
        print '%s|%s=%s;%s;%s' % (stat_line,arg_stat,perf_stat,arg_warning,arg_critical) 
    else:
        print '%s' % (stat_line)
    sys.exit(RETURN_VAL)
