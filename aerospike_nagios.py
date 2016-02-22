#!/usr/bin/python
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#
#

import sys
import types
import getopt
import re
import aerospike

# Nagios error codes:
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4

RETURN_VAL=STATE_OK

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
	print " -s \"statistic\" (Eg: \"free-pct-memory\")"
	print " -n \"namespace\" (Eg: \"namespace/test\")"
 	print " -c \"critical level\" (Eg: \"60\")"
 	print " -w \"warning level\" (Eg: \"70\")"
	return
###

###
## Process passed in arguments
try:
	opts, args = getopt.getopt(sys.argv[1:], "h:p:s:n::c:w:", ["host=","port=","statistics=","namespace","critical=","warning="])

	if not opts:
		print "No options supplied."
		print "%s" %args
		usage()
		sys.exit(-1)

## If we don't get in options passed print usage.
except getopt.GetoptError, err:
	print str(err)
	usage()
	sys.exit(-1)

for o, a in opts:
	if (o == "-h" or o == "--host"):
		arg_host = a
	if (o == "-p" or o == "--port"):
		arg_port = int(a)
	if (o == "-s" or o == "--statistics"):
		arg_stat = a
	if (o == "-n" or o == "--namespace"):
		arg_value = "namespace/" + a
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
			sys.exit(-1)
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
			sys.exit(-1)
		else:
			arg_warning = int(a)

# Make sure we have a statistic to look for
if arg_stat is None:
	print "A statistic was not supplied."
 	usage()
	sys.exit(-1)

if arg_critical is None:
	print "A critical was not supplied."
 	usage()
	sys.exit(-1)

if arg_warning is None:
	print "A warning value was not supplied."
 	usage()
	sys.exit(-1)

## /Process passed in arguments
###


#
# MAINLINE
#

config = {
        'hosts' : [ (arg_host, arg_port) ]
        }
client = aerospike.client(config).connect()
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

for arg in arg_stat.split():
	this_stat_line=""

	num_stat = None
	for s in r.split(";"):
		if arg + "=" in s:
			num_stat = s.split(arg + "=")[-1]
		if num_stat != None:
			this_stat_line = arg + "=" + num_stat

	if this_stat_line != "":
		if stat_line == None:
			stat_line='Aerospike Stats - ' + this_stat_line
		else:
			stat_line=stat_line + ' ' + this_stat_line

###
## Comparing the Aerospike value with the warning/critical passed values.
## Default comparison is if the Aerospike value is greater than the warning/critical value.
## Stats with "pct" in them are checked to see if the Aerospike value is less than the warning/critical value.
try:
    num_stat = int(num_stat)
except:
    pass
if "stop-writes" in arg_stat:
    if num_stat == 'true':
        RETURN_VAL=STATE_CRITICAL
    elif num_stat == 'false':
        RETURN_VAL=STATE_OK
    else:
        RETURN_VAL=STATE_UNKNOWN
if "free-pct" in arg_stat:
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
else:
	if arg_warning != 0: 
		if num_stat > arg_warning:
			RETURN_VAL=STATE_WARNING

	if arg_critical != 0:
		if num_stat > arg_critical:
			RETURN_VAL=STATE_CRITICAL

## /Comparison
###
		
###
## Print stat information and the return code for Nagios

if stat_line != "":
	print '%s' %(stat_line)
	sys.exit(RETURN_VAL)

## /Print
###
