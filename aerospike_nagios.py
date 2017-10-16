#!/usr/bin/env python
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#

# Copyright 2013-2017 Aerospike, Inc.
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
__copyright__ = "Copyright 2017 Aerospike"
__version__ = "1.4.1"

import sys
import yaml
import types
import socket
import re
import argparse
import struct
import time
import getpass
from ctypes import create_string_buffer

# Nagios error codes:
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4


schema_path = '/opt/aerospike/bin/aerospike_schema.yaml'
arg_value = "statistics"
stat_line = None

# =============================================================================
#
# Client
#
# -----------------------------------------------------------------------------

STRUCT_PROTO = struct.Struct('! Q')
STRUCT_AUTH = struct.Struct('! xxBB12x')
STRUCT_FIELD = struct.Struct('! IB')

MSG_VERSION = 0
MSG_TYPE = 2
AUTHENTICATE = 0
USER = 0
CREDENTIAL = 3
SALT = "$2a$10$7EqJtq98hPqEX7fNZaFWoO"

class ClientError(Exception):
        pass

class Client(object):

        def __init__(self, addr, port, timeout=0.7):
                self.addr = addr
                self.port = port
                self.timeout = timeout
                self.sock = None

        def connect(self, keyfile=None, certfile=None, ca_certs=None, ciphers=None, tls_enable=False, encrypt_only=False,
                capath=None, protocols=None, cert_blacklist=None, crl_check=False, crl_check_all=False, tls_name=None):
                s = None
                for res in socket.getaddrinfo(self.addr, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                        af, socktype, proto, canonname, sa = res
                        ssl_context = None
                        try:
                                s = socket.socket(af, socktype, proto)
                        except socket.error as msg:
                                s = None
                                continue
                        if tls_enable:
                                from ssl_context import SSLContext
                                from OpenSSL import SSL
                                ssl_context = SSLContext(enable_tls=tls_enable, encrypt_only=encrypt_only, cafile=ca_certs, capath=capath,
                                           keyfile=keyfile, certfile=certfile, protocols=protocols,
                                           cipher_suite=ciphers, cert_blacklist=cert_blacklist,
                                           crl_check=crl_check, crl_check_all=crl_check_all).ctx
                                s = SSL.Connection(ssl_context,s)
                        try:
                                s.connect(sa)
                                if ssl_context:
                                        s.set_app_data(tls_name)
                                        s.do_handshake()
                        except socket.error as msg:
                                s.close()
                                s = None
                                print "Connect Error" % msg
                                continue
                        break

                if s is None:
                        raise ClientError(
                                "Could not connect to server at %s %s" % (self.addr, self.port))

                self.sock = s
                return self

        def close(self):
                if self.sock is not None:
                        self.sock.settimeout(None)
                        self.sock.close()
                        self.sock = None

        def auth(self, username, password, timeout=None):

                import bcrypt

                credential = bcrypt.hashpw(password, SALT)

                if timeout is None:
                        timeout = self.timeout

                l = 8 + 16
                l += 4 + 1 + len(username)
                l += 4 + 1 + len(credential)

                buf = create_string_buffer(l)
                offset = 0

                proto = (MSG_VERSION << 56) | (MSG_TYPE << 48) | (l - 8)
                STRUCT_PROTO.pack_into(buf, offset, proto)
                offset += STRUCT_PROTO.size

                STRUCT_AUTH.pack_into(buf, offset, AUTHENTICATE, 2)
                offset += STRUCT_AUTH.size

                STRUCT_FIELD.pack_into(buf, offset, len(username) + 1, USER)
                offset += STRUCT_FIELD.size
                fmt = "! %ds" % len(username)
                struct.pack_into(fmt, buf, offset, username)
                offset += len(username)

                STRUCT_FIELD.pack_into(buf, offset, len(credential) + 1, CREDENTIAL)
                offset += STRUCT_FIELD.size
                fmt = "! %ds" % len(credential)
                struct.pack_into(fmt, buf, offset, credential)
                offset += len(credential)

                self.send(buf)

                buf = self.recv(8, timeout)
                rv = STRUCT_PROTO.unpack(buf)
                proto = rv[0]
                pvers = (proto >> 56) & 0xFF
                ptype = (proto >> 48) & 0xFF
                psize = (proto & 0xFFFFFFFFFFFF)

                buf = self.recv(psize, timeout)
                status = ord(buf[1])

                if status != 0:
                        raise ClientError("Autentication Error %d for '%s' " %
                                                          (status, username))

        def send(self, data):
                if self.sock:
                        try:
                                r = self.sock.sendall(data)
                        except IOError as e:
                                raise ClientError(e)
                        except socket.error as e:
                                raise ClientError(e)
                else:
                        raise ClientError('socket not available')

        def send_request(self, request, pvers=2, ptype=1):
                if request:
                        request += '\n'
                sz = len(request) + 8
                buf = create_string_buffer(len(request) + 8)
                offset = 0

                proto = (pvers << 56) | (ptype << 48) | len(request)
                STRUCT_PROTO.pack_into(buf, offset, proto)
                offset = STRUCT_PROTO.size

                fmt = "! %ds" % len(request)
                struct.pack_into(fmt, buf, offset, request)
                offset = offset + len(request)

                self.send(buf)

        def recv(self, sz, timeout):
                out = ""
                pos = 0
                start_time = time.time()
                while pos < sz:
                        buf = None
                        try:
                                buf = self.sock.recv(sz)
                        except IOError as e:
                                raise ClientError(e)
                        if pos == 0:
                                out = buf
                        else:
                                out += buf
                        pos += len(buf)
                        if timeout and time.time() - start_time > timeout:
                                raise ClientError(socket.timeout())
                return out

        def recv_response(self, timeout=None):
                buf = self.recv(8, timeout)
                rv = STRUCT_PROTO.unpack(buf)
                proto = rv[0]
                pvers = (proto >> 56) & 0xFF
                ptype = (proto >> 48) & 0xFF
                psize = (proto & 0xFFFFFFFFFFFF)

                if psize > 0:
                        return self.recv(psize, timeout)
                return ""

        def info(self, request):
                self.send_request(request)
                res = self.recv_response(timeout=self.timeout)
                out = re.split("\s+", res, maxsplit=1)
                if len(out) == 2:
                        return out[1]
                else:
                        raise ClientError("Failed to parse response: %s" % (res))

###
# Argument parsing
###
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-u'
                    , '--usage'
                    , '--help'
                    , action="help"
                    , help="Show this help message and exit")
parser.add_argument("-U"
                    , "--user"
                    , help="user name")
parser.add_argument("-P"
                    , "--password"
                    , nargs="?"
                    , const="prompt"
                    , help="password")
parser.add_argument("--credentials-file"
                    , dest="credentials"
                    , help="Path to the credentials file. Use this in place of --user and --password.")
parser.add_argument("-v"
                    , "--verbose"
                    , action="store_true"
                    , dest="verbose"
                    , help="Enable verbose logging")
group = parser.add_mutually_exclusive_group()
group.add_argument("-n"
                    , "--namespace"
                    , dest="namespace"
                    , help="Namespace name. eg: bar")
group.add_argument("-l"
                    , "--latency"
                    , dest="latency"
                    , help="Options: see output of asinfo -v 'latency:hist' -l")
group.add_argument("-x"
                    , "--xdr"
                    , dest="dc"
                    , help="Datacenter name. eg: myDC1")
parser.add_argument("-s"
                    , "--stat"
                    , dest="stat"
                    , required=True
                    , help="Statistic name. eg: cluster_size")
parser.add_argument("-p"
                    , "---port"
                    , dest="port"
                    , default=3000
                    , help="PORT for Aerospike server (default: %(default)s)")
parser.add_argument("-h"
                    , "--host"
                    , dest="host"
                    , default="127.0.0.1"
                    , help="HOST for Aerospike server (default: %(default)s)")
parser.add_argument("-c"
                    , "--critical"
                    , dest="crit"
                    , required=True
                    , help="Critical level")
parser.add_argument("-w"
                    , "--warning"
                    , dest="warn"
                    , required=True
                    , help="Warning level")
parser.add_argument("--tls_enable"
                    , action="store_true"
                    , dest="tls_enable"
                    , help="Enable TLS")
parser.add_argument("--tls_encrypt_only"
                    , action="store_true"
                    , dest="tls_encrypt_only"
                    , help="TLS Encrypt Only")
parser.add_argument("--tls_keyfile"
                    , dest="tls_keyfile"
                    , help="The private keyfile for your client TLS Cert")
parser.add_argument("--tls_certfile"
                    , dest="tls_certfile"
                    , help="The client TLS cert")
parser.add_argument("--tls_cafile"
                    , dest="tls_cafile"
                    , help="The CA for the server's certificate")
parser.add_argument("--tls_capath"
                    , dest="tls_capath"
                    , help="The path to a directory containing CA certs and/or CRLs")
parser.add_argument("--tls_protocols"
                    , dest="tls_protocols"
                    , help="The TLS protocol to use. Available choices: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or - can be appended before the protocol to indicate specific inclusion or exclusion.")
parser.add_argument("--tls_blacklist"
                    , dest="tls_blacklist"
                    , help="Blacklist including serial number of certs to revoke")
parser.add_argument("--tls_ciphers"
                    , dest="tls_ciphers"
                    , help="Ciphers to include. See https://www.openssl.org/docs/man1.0.1/apps/ciphers.html for cipher list format")
parser.add_argument("--tls_crl"
                    , dest="tls_crl"
                    , action="store_true"
                    , help="Checks SSL/TLS certs against vendor's Certificate Revocation Lists for revoked certificates. CRLs are found in path specified by --tls_capath. Checks the leaf certificates only")
parser.add_argument("--tls_crlall"
                    , dest="tls_crlall"
                    , action="store_true"
                    , help="Check on all entries within the CRL chain")
parser.add_argument("--tls_name"
                    , dest="tls_name"
                    , help="The expected name on the server side certificate")

args = parser.parse_args()

if args.dc:
  arg_value='dc/'+args.dc
elif args.namespace:
  arg_value='namespace/'+args.namespace
elif args.latency:
  arg_value='latency:hist='+args.latency

user = None
password = None

if args.user != None:
    user = args.user
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = args.password

if args.credentials:
    try:
        cred_file = open(args.credentials,'r')
        user = cred_file.readline().strip()
        password = cred_file.readline().strip()
    except IOError:
        print "Unable to read credentials file: %s"%args.credentials

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

try:
    client = Client(addr=args.host,port=args.port)
    client.connect(keyfile=args.tls_keyfile, certfile=args.tls_certfile, ca_certs=args.tls_cafile, ciphers=args.tls_ciphers, tls_enable=args.tls_enable,
                   encrypt_only=args.tls_encrypt_only, capath=args.tls_capath, protocols=args.tls_protocols, cert_blacklist=args.tls_blacklist,
                   crl_check=args.tls_crl,crl_check_all=args.tls_crlall, tls_name=args.tls_name)
except Exception as e:
    print("Failed to connect to the Aerospike cluster at %s:%s"%(args.host,args.port))
    print e
    sys.exit(STATE_UNKNOWN)
if user and password:
    status = client.auth(user,password)

r = client.info(arg_value).strip()
client.close()

if args.stat not in r:
    print "%s is not a known statistic." %args.stat
    sys.exit(STATE_UNKNOWN)

if r == -1:
    print "request to ",args.host,":",args.port," returned error."
    sys.exit(STATE_CRITICAL)
    
if r == None:
    print "request to ",args.host,":",args.port," returned no data."
    sys.exit(STATE_CRITICAL)


value = None
latency_time = ["1ms", "8ms", "64ms"]
if args.stat in latency_time:
    s = r.split(";")
    n = 1
    for t in latency_time:
        n += 1
        if t == args.stat:
            value = s[1].split(",")[n]
            args.stat = ">" + args.stat
        if value != None:
            stat_line = 'Aerospike Stats - ' + arg_value + ": " + args.stat + "=" + value
else:
    for s in r.split()[-1].split(";"):    # remove leading category, then split k=v tuples
        if s.startswith(args.stat + "="):
            value = s.split(args.stat + "=")[-1]
        if value != None:
            stat_line = 'Aerospike Stats - ' + args.stat + "=" + value

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
    if "operations" in schema[category] and args.stat in schema[category]["operations"]:
        uom = 'c'
        break
    if "bytes" in schema[category] and args.stat in schema[category]["bytes"]:
        uom = 'B'
        break
    if "percent" in schema[category] and args.stat in schema[category]["percent"]:
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
if "dc_state" in args.stat:
    if value != 'CLUSTER_UP':
        RETURN_VAL=STATE_CRITICAL
elif args.stat in ["stop_writes","system_swapping","hwm_breached","stop-writes","hwm-breached"]:
    if value == 'true':
        RETURN_VAL=STATE_CRITICAL
elif args.stat in ["cluster_integrity"]:
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
    if args.warn != "0":
        warn = parseRange(args.warn)
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
    if args.crit != "0":
        crit = parseRange(args.crit)
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
        print '%s|%s=%s;%s;%s' % (stat_line,args.stat,perf_stat,args.warn,args.crit) 
    else:
        print '%s' % (stat_line)
    sys.exit(RETURN_VAL)
