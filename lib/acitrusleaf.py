#!/usr/bin/python
####
#
#  Copyright (c) 2008-2012 Aerospike, Inc. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished
# to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####
# CitrusLeaf Aerospike python library
#
#

import sys  # please do not remove. used for stand alone build
import os
import socket  # socket needs no introduction
import struct  # gives us a parser/encoder for binary data

from ctypes import create_string_buffer  # gives us pre-allocated buffers

from time import time, sleep  # try to limit expansion of symbol tables?
import lib.util as util
import types
import threading
import traceback
import random


# AS_PROTO
# Offset  name meaning
# 0     version (1 byte)       the current version number = 2
# 1        type (1 byte)       AS_INFO = 1; AS_MSG = 3
# 2     size (6 bytes)         bytes to follow

# AS_MSG
# 0     header_sz              22 bytes currently
# 1     info1 (1 byte)         Bitfield of meaning see below
# 1     info2 (1 byte)         Bitfield of meaning see below
# 1     info3 (1 byte)         Bitfield of meaning see below
# 1     unused (1 byte)        Bitfield of meaning see below
# 1     result_code (1 bytes)  result of request
# 4     generation (4 bytes)   the incoming generation id, or returned
#                              generation id
# 8     record_ttl             record's TTL - seconds - when it will expire
# 12    transaction_ttl        transactions TTL - milliseconds - when it
#                              will expire
# 16    n_fields (2 bytes)     number of fields to follow
# 20    n_ops (2 bytes)        number of operations to follow
# 22    data (sz bytes)        payload

# 'info1' is a bitfield
# AS_MSG_INFO1_READ            (1 << 0)  // contains a read operation
# AS_MSG_INFO1_GET_ALL         (1 << 1)  // get all bins, period
# AS_MSG_INFO1_GET_ALL_NODATA  (1 << 2)  // get all bins WITHOUT data
#                                        // (currently unimplemented)
# AS_MSG_INFO1_VERIFY          (1 << 3)  // verify is a GET transaction that
#                                        // includes data, and assert if the
#                                        // data aint right

# AS_MSG_INFO2_WRITE           (1 << 0)  // contains a write semantic
# AS_MSG_INFO2_DELETE          (1 << 1)  // fling a record into the belly of
#                                        // Moloch
# AS_MSG_INFO2_GENERATION      (1 << 2)  // pay attention to the generation
# AS_MSG_INFO2_GENERATION_GT   (1 << 3)  // apply write if new generation >=
#                                        // old, good for restore
# AS_MSG_INFO2_GENERATION_DUP  (1 << 4)  // if a generation collision, create
#                                        // a duplicate
# AS_MSG_INFO2_WRITE_UNIQUE     (1 << 5) // write only if it doesn't exist
# AS_MSG_INFO2_WRITE_BINUNIQUE  (1 << 6)

# define AS_MSG_INFO3_LAST      (1 << 0) // this is the last of a multi-part
#                                        // message
# define AS_MSG_INFO3_TRACE     (1 << 1) // apply server trace logging for
#                                        // this transaction
# define AS_MSG_INFO3_TOMBSTONE (1 << 2) // if set on response, a version was
#                                        // a delete tombstone

AS_MSG_INFO1_READ           = 1
AS_MSG_INFO1_GET_ALL        = 2
AS_MSG_INFO1_GET_ALL_NODATA = 4
AS_MSG_INFO1_VERIFY         = 8

AS_MSG_INFO2_WRITE           = 1
AS_MSG_INFO2_DELETE          = 2
AS_MSG_INFO2_GENERATION      = 4
AS_MSG_INFO2_GENERATION_GT   = 8
AS_MSG_INFO2_GENERATION_DUP  = 16
AS_MSG_INFO2_WRITE_UNIQUE    = 32
AS_MSG_INFO2_WRITE_BINUNIQUE = 64

AS_MSG_INFO3_LAST      = 1
AS_MSG_INFO3_TRACE     = 2
AS_MSG_INFO3_TOMBSTONE = 4

# result_codes are as follows
# 0 success
# 1 not success

# AS_MSG_FIELD
# offset    name            meaning
# 0         sz (4 bytes)   number of bytes to follow
# 4         type (1 byte)   the type of the field
# 5         data (sz bytes) field-specific data

# types are:
# 0 namespace, a UTF-8 string
# 1 table, a UTF-8 string
# 2 key, one byte of type, then a type-specific set of bytes (see particle
# below)
# 3 bin, used for secondary access, one byte of namelength, the name, one byte
# of type, then the type-specific data

# AS_MSG_BIN
# offset    name           meaning
# 0         sz (4 bytes)      number of bytes to follow
# 4         op (1 byte)       operation to apply to bin
# 5         particle_type (1) type of following data
# 6         version (1)       can read multiple versions of the same record at
#                             once
# 7         name_len (1)      length of following utf8 encoded name
# 8         name (size = name_len)   utf8 encoded name
# 8+name_len data (size = sz - (3 + name_len))  particle specific data

# ops are:
# READ  -        1
# WRITE -        2
# WRITE_UNIQUE - 3 write a globally (?) unique value
# WRITE_NOW    - 4 write a timestamp of the current server value

# particle types are:
# INTEGER - 1    32-bit value
# BIGNUM  - 2 either an arbitrary precision integer, or a string-coded float,
# unsure yet
# STRING  - 3 UTF8 encoded
# ??
# BLOB    - 5 your arbitrary binary data

DEBUG = False

latency_func = None
socket_timeout = 0.7

def set_socket_timeout(timeout):
    global socket_timeout

    socket_timeout = timeout


def set_latency_func(func):
    global latency_func

    latency_func = func


def log_latency(op, start_time, end_time):
    global latency_func
    if latency_func != None:
        latency_func(op, start_time, end_time)


def log(*args):
    util.log('CITRUS', *args, stack_index=2)


my_random = None
random_owner = None
def bad_randint(first, last):
    global my_random, random_owner

    owner_id = "%s%s"%(os.getpid(),threading.current_thread().ident)
    if random_owner != owner_id:
        random_owner = owner_id
        my_random = random.SystemRandom(time() + os.getpid() + 
                                        threading.current_thread().ident)
        my_random = my_random.randint
        if threading.current_thread().name != 'MainThread':
            # hope that child processes do not spawn children.
            sys.modules[__name__].bad_randint = my_random

    return my_random(first, last)


def my_unpack_from(fmtstr, buf, offset):
    sz = struct.calcsize(fmtstr)
    return struct.unpack(fmtstr, buf[offset:offset + sz])


def my_pack_into(fmtstr, buf, offset, *args):
    tmp_array = struct.pack(fmtstr, *args)
    buf[offset:offset + len(tmp_array)] = tmp_array


# def ripemd160(sett, key):
#     raise NotImplementedError('TODO: make it work :b')
#     h = hashlib.new('ripemd160')
#     h.update(bytes(sett))
#     h.update(bytes(key))
#     h.update(ParticleType.getType(key))
#     return h.hexdigest()


g_proto_header = struct.Struct('! Q')
g_struct_header_in = struct.Struct('! Q B 4x B I 8x H H')
g_struct_header_out = struct.Struct('! Q B B B B B B I I I H H')
g_struct_bin = struct.Struct("! I B B B B")


class ClientException(Exception):
    pass


class Particle(object):
    # Server particle types. Unsupported types are commented out.
    NULL            = 0
    INTEGER         = 1
    BIGNUM          = 2
    STRING          = 3
    BLOB            = 4
    TIMESTAMP       = 5
    DIGEST          = 6
    JBLOB           = 7
    CSHARP_BLOB     = 8
    PYTHON_BLOB     = 9
    RUBY_BLOB       = 10
    PHP_BLOB        = 11
    ERLANG_BLOB     = 12
    SEGMENT_POINTER = 13
    RTA_LIST        = 14
    RTA_DICT        = 15
    RTA_APPEND_DICT = 16
    RTA_APPEND_LIST = 17
    LUA_BLOB        = 18
    MAP             = 19
    LIST            = 20

    @classmethod
    def getType(cls, key):
        if isinstance(key, (int, long)):
            retval = cls.INTEGER
        if isinstance(key, str):
            retval = cls.STRING
        else:
            raise TypeError("Unknown Type For %s"%(type(key)))

        return bytes([retval])


class ReturnCode(object):
    # Client return codes
    client_error   = -1
    client_timeout = -2

    # Server return codes
    ok                   = 0
    server_error         = 1
    key_not_found        = 2
    generation_error     = 3
    parameter_error      = 4
    key_exists_error     = 5
    bin_exists_error     = 6
    cluster_key_mismatch = 7
    server_mem_error     = 8
    timeout              = 9
    no_xds               = 10
    server_not_available = 11
    bin_type_error       = 12
    record_too_big       = 13
    key_busy             = 14
    scan_abort           = 15
    unsupported_feature  = 16


class Socket(object):
    """
    Citrusleaf socket: container class for a socket, which allows
    incrementing of timers and statuses easily
    """
    def __init__(self, host_obj):
        self.s = None
        self.host_obj = host_obj
        self.debug = DEBUG

    def connect(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            if self.debug:
                print "first exception - can't even create socket" + \
                      "- don't dun host", msg
            return False
        try:
            self.s.settimeout(socket_timeout)
            self.s.connect(self.host_obj.sockaddr[0])
        except socket.error, msg:
            if self.debug:
                print " connect exception "
            self.s.close()
            self.host_obj.markBad()
            if self.debug:
                print 'could not open socket, maybe its not up?'
            return False
        self.host_obj.markGood()
        return True

    def send(self, data):
        try:
            r = self.s.sendall(data)
        except socket.error, msg:
            if self.debug:
                print " send exception ", msg
            return False
        if r != None:
            if self.debug:
                print " send returned error but not exception "
            return False
        return True

    # it's better to let this throw
    def recv(self, data):
        pos = 0
        start_time = time()
        while pos < data:
            b = self.s.recv(data)
            if pos == 0:
                r = b
            else:
                r += b
            pos += len(b)
            if time() - start_time > socket_timeout:
                raise socket.timeout()
        return r

    # Close in case of a successful connection
    def close(self):
        if len(self.host_obj.idle_sockets) < 128:
            self.s.settimeout(None)  # make sure it doesn't expire in q
            self.host_obj.idle_sockets.append(self)
        else:
            self.s.close()
            self.s = None
        return

    # return with error
    def close_err(self):
        self.host_obj.markBad()
        self.s.close()
        self.s = None


class Host(object):
    """
    Citrusleaf Host: container class for all the little bits that make up a
    host
    """

    def __init__(self, cluster):
        self.sockaddr = []  # list of sockaddrs where this node can be found
        self.idle_sockets = []
        self.node = 0
        self.family = None
        self.socktype = None
        self.cluster = cluster    # think of it as a parent pointer
        self.debug = DEBUG

    def __str__(self):
        return str({"node":self.node
                    , "sockaddr":self.sockaddr})

    def markBad(self):
        if self.debug:
            print "Marking bad: ", self.node, " ", self.sockaddr[0]
        self.cluster.markBad(self)

    def markGood(self):
        self.cluster.markGood(self)

    # called to get a connection to this host,
    # either from the pool or by creating a new connection
    # through a connect call
    def getConnection(self):
        try:
            s = self.idle_sockets.pop(0)
            s.s.settimeout(socket_timeout)
            return s
        except:
            pass
        s = Socket(self)
        if s.connect() == True:
            return s
        else:
            if self.debug:
                print "host ", self.sockaddr[0], " connection failed"
        return None

    def close(self):
        try:
            while True:
                s = self.idle_sockets.pop()
                s.close()
        except:
            pass
        self.idle_sockets = None


class Cluster(object):
    def __init__(self):
        self.hosts_known = dict()
        self.hosts_unknown = dict()
        self.crawler_disable = False  # terminate crawler
        self.next_crawl = 0
        self.crawl_period = 1.5
        self.debug = DEBUG

    def __str__(self):
        return str({'hosts_known': [(i[0], i[1].sockaddr)
                                    for i in self.hosts_known.iteritems()]
                    , 'hosts_unknown': [(i[0], i[1].sockaddr)
                                        for i in self.hosts_unknown.iteritems()]})

    def __len__(self):
        return len(self.hosts_known)

    def getHosts(self):
        return (host.sockaddr for host in self.hosts_known.itervalues())

    def addHost(self, host, port):
        for _ in xrange(3):
            # try 3 times
            host_id = info(host, port, "node")
            if host_id != -1 and host_id != '':
                break

        if host_id == -1 or host_id == '':
            if self.debug:
                print "Cannot add unresponsive host %s:%s"%(host, port)
            return

        if host_id in self.hosts_unknown:
            self.hosts_known[host_id] = self.hosts_unknown[host_id]
            del self.hosts_unknown[host_id]
            return

        if host_id in self.hosts_known:
            return

        # A real new host
        for host_info in socket.getaddrinfo(host
                                            , port
                                            , socket.AF_UNSPEC
                                            , socket.SOCK_STREAM):
            host_obj = Host(self)
            host_obj.family, host_obj.socktype, host_obj.proto, canonname, sa = host_info
            host_obj.node = host_id
            host_obj.sockaddr.append(sa)
            self.hosts_known[host_id] = host_obj

    def crawl(self):
        if not self.crawler_disable:
            if self.debug:
                print "Crawler: Crawling!"
            self._probeNodes()
            self.next_crawl = time() + self.crawl_period

    def _probeNodes(self):
        # no lets just test them all

        all_hosts = []
        all_hosts.extend(self.hosts_known.values())
        if len(all_hosts) == 0:
            # If we do not have any known, try the unknown status.
            # If we have known lets pickup the unknown when they appear in the
            # services listing.
            all_hosts.extend(self.hosts_unknown.values())
            log("all hosts down, trying down hosts")

        if self.debug:
            print "crawler: probeNodes Before", self

        if not all_hosts:
            log("error: all hosts GONE!!")
            return

        all_services = set()
        retrys = 10
        for host in all_hosts:
            for i in xrange(retrys):
                services = info(host.sockaddr[0][0]
                                , host.sockaddr[0][1]
                                , 'services')
                if services != -1:
                    break
                sleep(0.01)
            else:
                log('DEBUG', str(host)
                    , "service request returned -1 %s times"%(retrys))
                self.markBad(host)
                continue

            wire_services = services

            all_services.add(tuple(host.sockaddr[0]))

            services = services.split(';')
            for service in services:
                if service == '':
                    continue
                # convert string to sockaddr
                try:
                    host, port = service.split(':')
                    port = int(port)
                    all_services.add((host, port))
                except Exception as e:
                    except_type, except_class, tb = sys.exc_info()
                    log('DEBUG', 'wire_services'
                        , "%r"%(wire_services)
                        , type(e)
                        , str(e)
                        , traceback.extract_tb(tb))

        for service in all_services:
            self.addHost(service[0], service[1])

        if self.debug:
            print "crawler: probeNodes After", self

    def getConnection(self, node_index=None):
        """
        If node is None, select a random node, otherwise use provided node.
        """

        c = None
        trys = 6

        for _ in xrange(trys):
            current_time = time()
            if len(self.hosts_known) <= 1 or self.next_crawl < current_time:
                self.crawl()
                if len(self.hosts_known) <= 1:
                    log("%s known, %s unknown"%(len(self.hosts_known)
                                                , len(self.hosts_unknown)))
                    continue

            # sort keys so we when I specify node_index = x, I will normally get
            # the appropriate node
            host_keys = sorted(self.hosts_known.keys())

            if node_index != None and isinstance(node_index, int):
                index = node_index % len(host_keys)
            else:
                index = bad_randint(0, len(host_keys) -1)
            host_id = host_keys[index]
            c = self.hosts_known[host_id].getConnection()
            if c:
                break  # We have nodes

        return c

    def markGood(self, host):
        pass
        # TODO: Why does the following cause nodes to disappear from both
        #       known and unknown?
        # if host.node in self.hosts_unknown:
        #     self.crawl()

    def markBad(self, host):
        if self.debug:
            print "Crawler: Marking Bad"
        if host.node in self.hosts_known:
            self.hosts_unknown[host.node] = self.hosts_known[host.node]
            del self.hosts_known[host.node]
            self.crawl()

    def close(self):
        # this section must stop the crawler thread - need to get a signal back
        self.crawler_disable = True
        for host in self.hosts_known:
            host.close()
        for host in self.hosts_unknown:
            host.close()

#
# Make an info request of the buffer
#
info_sockets = {}

def info_request(host, port, buf, debug=False):
    # request over TCP
    sock_key = (host, int(port))
    if sock_key not in info_sockets:
        for _ in xrange(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5) # Allow these a bit longer,
                                     # they open NEW sockets
                sock.connect(sock_key)
            except socket.error as se:
                continue
            else:
                log('new socket opened', host, port)
                break
        else:  # if for does not break on it's own
            log('could not open socket to', host, port)
        info_sockets[sock_key] = sock

    sock = info_sockets[sock_key]
    try:
        sock.send(buf)

        if debug:
            print "info get response"
        # get response
        rsp_hdr = sock.recv(8)
        if debug:
            print "response is: "
            _hexlify(rsp_hdr)
        q = struct.unpack_from("! Q", rsp_hdr, 0)
        sz = q[0] & 0xFFFFFFFFFFFF
        if debug:
            print "recv header length ", sz
        if sz > 0:
            pos = 0
            start_time = time()
            while pos < sz:
                tmp_data = sock.recv(sz - pos)
                if pos == 0:
                    rsp_data = tmp_data
                else:
                    rsp_data += tmp_data
                pos += len(tmp_data)
                if start_time - time() > 1.0:
                    raise socket.timeout
            if debug:
                print "recv body "
                _hexlify(rsp_data)
    except Exception:
        del info_sockets[sock_key]
        sock.close()
        log('socket error', 'closed', host, port)
        return ReturnCode.client_error

    # parse out responses
    if sz == 0:
        return None

    if debug:
        print "receive as string: ", rsp_data

    return rsp_data


def info_command(host, port, cmd, parameters=None, debug=False):
    """
    Citrusleaf Info Command

    This is a special purpose request to do things to the citrusleaf cluster
    for a given node.

    pass in the command - which is a command string, and a dict
    of name-value pairs.

    Wire format is cmd:name=value;name=value....

    Returns: values, a dict of with the name being the index, and the value
    being the value
    """
    # Passed a set of names: created output buffer
    param_l = []
    param_l.append(cmd)
    param_l.append(":")
    if parameters != None:
        for name, value in parameters.iteritems():
            param_l.append(name)
            param_l.append("=")
            param_l.append(value)
            param_l.append(";")
        del param_l[len(param_l) - 1]
    param_l.append("\n")
    paramstr = "".join(param_l)
    # sometimes this string is unicode, if the parameters input were unicode
    # not string
    # force to string just to be sure - this may be required elsewhere -
    # different versions of python are different about how they type stuff
    # like this
    paramstr = str(paramstr)

    q = (2 << 56) | (1 << 48) | (len(paramstr))
    fmtstr = "! Q %ds" % len(paramstr)
    buf = struct.pack(fmtstr, q, paramstr)

    if debug:
        print "info cmd request buffer: "
        _hexlify(buf)

    rsp_data = info_request(host, port, buf, debug)

    if debug:
        print "citrusleaf info: response ", rsp_data
    return rsp_data


def _info(host, port, names=None, debug=False):
    """
    Citrusleaf Info request

    This is a special purpose request to get informational name-value pairs
    from a given node. It's good for discovering the rest of the cluster,
    or trying to figure out which cluster members have which parts of the key
    space

    host, port are self explanatory
    'names' is an iterable list of values to get, or None to get all
    being really nice, also supporting a single string as a name instead of
    requiring a list

    Returns: values, a dict of with the name being the index, and the value
    being the value
    """

    # Passed a set of names: created output buffer

    if names == None:
        q = (2 << 56) | (1 << 48)
        buf = g_proto_header.pack(q)

    elif type(names) == types.StringType:
        q = (2 << 56) | (1 << 48) | (len(names) + 1)
        fmtstr = "! Q %ds B" % len(names)
        buf = struct.pack(fmtstr, q, names, 10)
    else:  # better be iterable of strings
           # annoyingly, join won't post-pend a seperator. So make a new list
           # with all the seps in
        namestr = "".join(["%s\n"%(name) for name in names])
        q = (2 << 56) | (1 << 48) | (len(namestr))
        fmtstr = "! Q %ds" % len(namestr)
        buf = struct.pack(fmtstr, q, namestr)

    if debug:
        print "request buffer: "
        _hexlify(buf)

    rsp_data = info_request(host, port, buf, debug)

    if rsp_data == -1 or rsp_data is None:
        return ReturnCode.client_error

    # if the original request was a single string, return a single string
    if type(names) == types.StringType:

        lines = rsp_data.split("\n")
        name, sep, value = lines[0].partition("\t")

        if name != names:
            if debug:
                print " problem: requested name ", names, " got name ", name
            return -1
        return value

    else:
        rdict = dict()
        for line in rsp_data.split("\n"):
            if len(line) < 1:
                # this accounts for the trailing '\n' - cheaper than chomp
                continue
            if debug:
                print " found line ", line
            name, sep, value = line.partition("\t")
            if debug:
                print "    name: ", name, " value: ", value
            rdict[name] = value

        return rdict


def info(host, port, names=None, debug=False, trys=1):
    for i in xrange(trys):
        result = _info(host
                      , port
                      , names=names
                      , debug=debug)
        if result != '' and result != -1:
            break

        if trys != i-1:
            sleep(0.1)

    return result

def e_info(host, port, names=None, debug=False, trys=1):
    result = info(host
                  , port
                  , names=names
                  , debug=debug
                  , trys=trys)

    if result == '' or result == -1:
        raise IOError("Unable to issue info request to %s:%s"%(host
                                                               , port))

    return result


def find_hosts(seed_address, seed_port, use_alumni=False):
    command = 'services-alumni' if use_alumni else 'services'

    result = []
    try:
        result.append(e_info(seed_address, seed_port, command, trys=5))
    except IOError:
        pass

    seed_address = socket.gethostbyname(seed_address)
    result.append("%s:%s"%(seed_address, seed_port))
    result = ';'.join(result)
    hosts = map(util.info_to_tuple, util.info_to_list(result))

    return hosts


def find_namespaces(address, port):
    result = e_info(address, port, 'namespaces', trys=5)
    return util.info_to_list(result)


def info_namespace_stats(address, port):
    namespaces = find_namespaces(address, port)
    rv = {}
    for namespace in namespaces:
        rv[namespace] = util.info_to_dict(
            e_info(address, port, "namespace/%s"%(namespace)))

    return rv


def info_statistics(host, port, debug=False):
    """
    Convienence funtion to return statistics information as a dictionary.
    """

    rv = e_info(host, port, names="statistics", debug=debug)

    return util.info_to_dict(rv)


def _hexlify(buf):
    print "my hexlify: length ", len(buf)
    for i, c in enumerate(buf):
        print "%02x " % ord(c),
        if i % 16 == 15:
            print ""
        elif i % 16 == 7:
            print ": ",
    print


def transaction(cluster
                , data
                , autoretry=True
                , debug=False
                , op='unk'
                , node_index=None):
    """
    host and port are strings, data is the prebuilt buffer

    returns: result_code, generation, dictionary of responses

    dictionary is:
    bin name => value
    """

    result_code = ReturnCode.client_error
    generation = None
    op_dict = None
    retrys = 3 if autoretry else 1

    #transaction_id = bad_randint(100000000, 999999999)
    #log("Start transaction", transaction_id)

    if debug:
        print "Entering transmit loop"

    for trys in xrange(retrys):
        s = cluster.getConnection(node_index=node_index)

        if s != None:
            break  # Got a connection

        if debug:
            print "failed to get connection, try: %s of %s"%(trys, retrys)
        # retry
    else:  # unable to get connection
        if debug:
            print "failed to get a connection"
        return result_code, generation, op_dict, 'unknown'

    op_dict = None

    if s == None or s.s == None:
        host = 'unknown'
    else:
        host = str(s.s.getpeername())

    try:
        start_time = time()
        s.send(data)
        header_data = s.recv(30)    # fetch header
        end_time = time()
        log_latency(op, start_time, end_time)
        proto_type, result_code, generation, n_fields, n_ops, sz = parse_header(header_data, debug)
        if sz:
            body_data = s.recv(sz)
            op_dict = parse_body(n_fields, n_ops, body_data, debug)
    except socket.timeout:
        s.close_err()
        result_code = ReturnCode.client_timeout
    except Exception, msg:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        log("transaction error", "other"
            , msg, type(msg), exc_type, exc_tb.tb_lineno)
        s.close_err()
    else:
        # successful request out here
        s.close()

    if debug:
        print "Exit transmit loop"

    return result_code, generation, op_dict, host


def parse_header(buf, debug=False):
    """
    precompile is better: will be used lots
    Q is version + type + length
    B header size (22)
    B info , B info2, B info3, B unused (so uninteresting on read, bring them
    into one value)
    B result code (0 is OK)
    I generation
    I record_ttl
    I transaction_ttl
    H n_fields
    H n_ops

    struct.Struct is a great optimization, but is >= 2.5, so code
    both ways, sorry for the ugly

    returns
    ( type, result_code, generation, n_fields, n_ops, sz )
    sz is remainder of the message (not the size in the header)
    record_ttl is not interesting thus not returned
    transaction_ttl is not interesting thus not returned
    same with the info fields
    """

    if debug == True:
        print "parse header: received header: "
        _hexlify(buf)

    rv = g_struct_header_in.unpack(buf)

    version = (rv[0] >> 56) & 0xFF
    proto_type = (rv[0] >> 48) & 0xFF
    sz = (rv[0] & 0xFFFFFFFFFFFF)

    if version != 2:
        if debug:
            print "protocol version mismatch! expecting 2 got ", version
    if rv[1] != 22:
        if debug:
            print "protocol header parse: unexpected header size", rv[1]

    return (proto_type, rv[2], rv[3], rv[4], rv[5], sz - 22)


def parse_body(n_fields, n_ops, buf, debug=False):
    """
    input: the number of fields and the number of ops and the buffer itself
    (todo: parse fields, currently nothing returns fields)
    return:
    """
    if n_fields != 0:
        if debug:
            print "todo: parse body with nfields, error"
        return None

    # short circut
    if n_ops == 0:
        if len(buf) > 0:
            if debug:
                print "parse body: curious, told no ops but there's data here"
        return None

    # loud debugging
    #if debug:
    #    print "read body: "
    #    _hexlify(buf)

    # print "parse body: buf size ",len(buf)," nops to parse: ",n_ops

    bin_dict = {}
    offset = 0
    for _ in xrange(n_ops):
        sz, op, p_type, vers, bin_sz = g_struct_bin.unpack_from(buf, offset)
        offset = offset + 8
        fmtstr = "%ds" % bin_sz
        bin_name = struct.unpack_from(fmtstr, buf, offset)
        bin_name = bin_name[0]
        offset = offset + bin_sz


        p_size = sz - (4 + len(bin_name))

        # deal with the bin's binary data - convert to a value and jam into
        # the dict

        # TODO! take the different versions and put them in different buckets

        if p_type == Particle.NULL:
            bin_dict[bin_name] = None

        elif p_type == Particle.INTEGER:
            val_int = g_proto_header.unpack_from(buf, offset)
            bin_dict[bin_name] = val_int[0]
            offset = offset + 8

        # strings and blobs are the same in python
        elif p_type == Particle.STRING or p_type == Particle.BLOB:
            up_str = "%ds" % p_size
            val_str = struct.unpack_from(up_str, buf, offset)
            bin_dict[bin_name] = val_str[0]
            offset += p_size

    return bin_dict


def generic_header_out_pack(buf
                            , sz
                            , info1
                            , info2
                            , info3
                            , generation
                            , record_ttl
                            , transaction_ttl
                            , n_bins):
    offset      = 0
    header_sz   = 22
    unused      = 0
    result_code = 0
    n_fields    = 3  # number of fields to follow
    # info1
    # info2
    # info3
    generation = generation or 0
    record_ttl = record_ttl or 0
    transaction_ttl = transaction_ttl or 0
    # n_ops == n_bins ?

    # pack up that first quadword
    sz = (2 << 56) | (3 << 48) | (sz - 8)

    g_struct_header_out.pack_into(buf
                                 , offset
                                 , sz
                                 , header_sz
                                 , info1
                                 , info2
                                 , info3
                                 , unused
                                 , result_code
                                 , generation
                                 , record_ttl
                                 , transaction_ttl
                                 , n_fields
                                 , n_bins)
    return g_struct_header_out.size


def generic_key_size(key, namespace, sett):
    sz = 0
    key_type = type(key)
    if key_type == types.StringType:
        len_key = len(key)
        sz += (3 * 5) + len(namespace) + len(sett) + len_key + 1   # fields
    elif key_type == types.IntType:
        len_key = 8  # integer is of fixed 8 bytes
        sz += (3 * 5) + len(namespace) + len(sett) + len_key + 1   # fields
    elif key_type == bytearray or key_type == types.ListType:
        len_key = 20  # digest is of fixed 20 bytes
        sz += (3 * 5) + len(namespace) + len(sett) + len_key   # fields
    else:
        raise ClientException("Unknown key type: %s"%(key_type))

    return len_key, sz


def generic_key_pack(buf, offset, namespace, sett, key, len_key):
    key_type = type(key)
    len_namespace = len(namespace)
    len_sett = len(sett)
    if key_type == types.StringType:
        fmtstr = "! I B %ds I B %ds I B B %ds" % (len_namespace
                                                  , len_sett
                                                  , len_key)
        struct.pack_into(fmtstr
                         , buf
                         , offset
                         , len_namespace + 1
                         , 0
                         , namespace
                         , len_sett + 1
                         , 1
                         , sett
                         , len_key + 2
                         , 2
                         , 3
                         , key)
        offset += (3 * 5) + len_namespace + len_sett + len_key + 1
    elif key_type == types.IntType:
        fmtstr = "! I B %ds I B %ds I B B Q" % (len_namespace, len_sett)
        struct.pack_into(fmtstr
                         , buf
                         , offset
                         , len_namespace + 1
                         , 0
                         , namespace
                         , len_sett + 1
                         , 1
                         , sett
                         , len_key + 2
                         , 2
                         , 1
                         , key)
        offset += (3 * 5) + len_namespace + len_sett + len_key + 1
    elif key_type == bytearray or key_type == types.ListType:
        fmtstr = "! I B %ds I B %ds I B 20B" % (len_namespace, len_sett)
        struct.pack_into(fmtstr
                         , buf
                         , offset
                         , len_namespace + 1
                         , 0
                         , namespace
                         , len_sett + 1
                         , 1
                         , sett
                         , len_key + 1
                         , 4
                         , key[0], key[1], key[2], key[3], key[4]
                         , key[5], key[6], key[7], key[8], key[9]
                         , key[10], key[11], key[12], key[13], key[14]
                         , key[15], key[16], key[17], key[18], key[19])
        offset += (3 * 5) + len_namespace + len_sett + len_key
    else:
        raise ClientException("Unknown key type: %s"%(key_type))

    return offset


def put_bins_size(values):
    sz = 0
    for binn, value in values.iteritems():
        value_type = type(value)
        len_binn = len(binn)
        if type(binn) != types.StringType:
            raise ClientException("Citrusleaf bin names must be string, %s"%(type(binn)))
        elif value_type == types.StringType:
            sz += 8 + len_binn + len(value)
        elif value_type == types.IntType:
            sz += 8 + len_binn + 8
        elif value_type == types.NoneType:
            sz += 8 + len_binn
        else:
            raise ClientException("Citrusleaf found bin of unknonw type %s"%(type(value)))
    return sz


def get_bins_size(binn):
    sz = 0

    binn_type = type(binn)
    if binn_type == types.NoneType:
        return sz
    elif binn_type != types.TupleType or binn_type != types.ListType:
        raise ClientException("bin type unknown %s"%(type(binn)))

    for b in binn:
        if type(b) == types.StringType:
            sz += 8 + len(b)
        else:
            raise ClientException("Found bin of unknown type %s"%(type(b)))
    return sz


def put_bins_pack(buf, offset, values, stringsAsBlobs):
    for binn, value in values.iteritems():
        len_bin = len(binn)
        value_type = type(value)
        if value_type == types.StringType:
            bin_sz = 4 + len_bin + len(value)
            fmtstr = "! I B B B B %ds %ds"%(len_bin, len(value))
            # type 4 is blob - represent strings as blobs
            if stringsAsBlobs == True:
                struct.pack_into(fmtstr
                                 , buf
                                 , offset
                                 , bin_sz
                                 , 2
                                 , 4
                                 , 0
                                 , len_bin
                                 , binn
                                 , value)
            else:
                struct.pack_into(fmtstr
                                 , buf
                                 , offset
                                 , bin_sz
                                 , 2
                                 , 3
                                 , 0
                                 , len_bin
                                 , binn
                                 , value)
        elif value_type == types.IntType:
            bin_sz = 4 + len_bin + 8
            fmtstr = "! I B B B B %ds Q" % len_bin
            struct.pack_into(fmtstr
                             , buf
                             , offset
                             , bin_sz
                             , 2
                             , 1
                             , 0
                             , len_bin
                             , binn
                             , value)
        elif value_type == types.NoneType:
            bin_sz = 4 + len_bin
            fmtstr = "! I B B B B %s" % len_bin
            struct.pack_into(fmtstr
                             , buf
                             , offset
                             , bin_sz
                             , 2
                             , 0
                             , 0
                             , len_bin
                             , binn)

        else:
            raise ClientException("Unknown value type: %s"%(value_type))

        offset += bin_sz + 4

    return offset


def get_bins_pack(buf, offset, binn):
    binn_type = type(binn)
    if binn_type == types.TupleType or binn_type == types.ListType:
        for b in binn:
            b_len = len(b)
            if type(b) == types.StringType:
                # now one bin - just hard code op 1 (read), particle type 3
                # (string)
                bin_sz = 4 + b_len
                fmtstr = "! I B B B B %ds" % b_len
                struct.pack_into(fmtstr
                                 , buf
                                 , offset
                                 , bin_sz
                                 , 1
                                 , 0
                                 , 0
                                 , b_len
                                 , b)
                offset = offset + bin_sz
            else:
                raise ClientException("Bin name is not a string, instead %s"%(type(b)))
    elif binn_type == types.NoneType:
        pass
    else:
        raise ClientException("Unable to format output: bin type %s"%(binn))

    return offset


def put(cluster
        , namespace
        , sett
        , key
        , values
        , record_ttl=None
        , transaction_ttl=None
        , generation=None
        , autoretry=True
        , debug=False
        , stringsAsBlobs=False):
    """
    put is more and more complicated!
    return a result code only, whether the put suceeded or not

    record_ttl is the time from now, in seconds, when the database will
    auto-remove the record
    transaction_ttl is the lifetime of the transaction, in milliseconds
    (currently not implemented)
    the generation count is the current generation of the record, used for
    locking read-modify-write
    auto-retry allows

    stringsAsBlobs is a special argument that treats all incoming strings as
    'blob' types to the server

    if you want to insert through digest then set key as the digest value and
    digest parameter as True
    """
    # for fastest action, create the entire buffer size up front

    try:
        lenkey, sz = generic_key_size(key, namespace, sett)
        sz += 30 # header
        sz += put_bins_size(values)
    except ClientException as e:
        if debug:
            print "Exception occured in put: %s"%(str(e))
        return ReturnCode.client_error


    n_bins = len(values)

    buf = create_string_buffer(sz)  # from ctypes - important to going fast!
    info1 = 0
    info2 = AS_MSG_INFO2_WRITE
    info3 = 0

    if generation != None:
        info2 = info2 | AS_MSG_INFO2_GENERATION

    stringsAsBlobs = stringsAsBlobs or False

    try:
        offset = generic_header_out_pack(buf, sz, info1, info2, info3, generation
                                         , record_ttl, transaction_ttl, n_bins)
        offset = generic_key_pack(buf, offset, namespace, sett, key, lenkey)
        offset = put_bins_pack(buf, offset, values, stringsAsBlobs)
    except ClientException as e:
        if debug:
            print "Exception occured in put: %s"%(str(e))
        return ReturnCode.client_error

    # # loud debugging
    # if debug:
    #     print "transmit put buffer: "
    #     _hexlify(buf)

    result_code, generation, bins, host = transaction(cluster
                                                      , buf
                                                      , autoretry
                                                      , debug
                                                      , op='put')

    return result_code


def get(cluster
        , namespace
        , sett
        , key
        , binn=None
        , transaction_ttl=None
        , autoretry=True
        , debug=False
        , node_index=None):
    """
    Pass bin as None (or ignore the parameter) to select all
    Or pass in a list or tuple to get those bins
    or pass in a string to get just that bin

    The response is (result_code, generation, bins)
    """
    if type(binn) == types.StringType:
        binn = (binn)

    try:    
        n_bins = len(binn)
    except TypeError:
        n_bins = 0  # binn should be None

    # figure out the size of the whole output message
    try:
        lenkey, sz = generic_key_size(key, namespace, sett)
        sz += 30 # header
        sz += get_bins_size(binn)
    except ClientException as e:
        if debug:
            print "Exception occured in put: %s"%(str(e))
        return ReturnCode.client_error, 0, None

    if debug:
        print "transmitting get request for ", n_bins, " bins"

    buf = create_string_buffer(sz)    # from ctypes

    # this is a read op
    info1 = AS_MSG_INFO1_READ
    if binn == None:
        info1 = info1 | AS_MSG_INFO1_GET_ALL
    info2 = 0
    info3 = 0

    try:
        offset = generic_header_out_pack(buf, sz, info1, info2, info3, 0
                                         , 0, transaction_ttl, n_bins)
        offset = generic_key_pack(buf, offset, namespace, sett, key, lenkey)
        offset = get_bins_pack(buf, offset, binn)
    except ClientException as e:
        if debug:
            print "Exception occured in get: %s"%(str(e))
        return ReturnCode.client_error, 0, None

    # # loud debugging
    # if debug:
    #     print "transmit get buffer: "
    #     _hexlify(buf)

    return transaction(cluster, buf, autoretry, debug, op='get', node_index=node_index)


def consistent_get(cluster
                   , namespace
                   , sett
                   , key
                   , transaction_ttl=None
                   , binn=None
                   , autoretry=True
                   , debug=False):
    gets = []
    for node_index in xrange(len(cluster)):
        gets.append(get(cluster, namespace, sett, key
                        , binn=binn, autoretry=autoretry, debug=debug
                        , node_index=node_index))
    return zip(cluster.getHosts(), gets)


def delete(cluster
           , namespace
           , sett
           , key
           , generation=None
           , transaction_ttl=None
           , autoretry=True
           , debug=False):
    # figure out the size of the whole output message
    try:
        lenkey, sz = generic_key_size(key, namespace, sett)
        sz += 30 # header
    except ClientException as e:
        if debug:
            print "Exception occured in delete: %s"%(str(e))
        return ReturnCode.client_error

    buf = create_string_buffer(sz)        # from ctypes

    # 3 is nfields, 1 is n_ops
    info1 = 0
    info2 = AS_MSG_INFO2_WRITE | AS_MSG_INFO2_DELETE
    if generation != None:
        info2 = info2 | AS_MSG_INFO2_GENERATION
    info3 = 0

    try:
        offset = generic_header_out_pack(buf, sz, info1, info2, info3, 0
                                         , 0, transaction_ttl, 0)
        offset = generic_key_pack(buf, offset, namespace, sett, key, lenkey)
    except ClientException as e:
        if debug:
            print "Exception occured in delete: %s"%(str(e))
        return ReturnCode.client_error


    result_code, generation, bins = transaction(cluster
                                                , buf
                                                , autoretry
                                                , debug
                                                , op='delete')

    # # loud debugging
    # if debug:
    #     print "transmit get buffer: "
    #     _hexlify(buf)

    return result_code
