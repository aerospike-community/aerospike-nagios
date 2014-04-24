import re
import itertools
import threading
import inspect # for log()
import sys
import socket
from time import time


def info_to_dict(value, delimiter=';'):
    """
    Simple function to convert string to dict

    Arguments:
    value -- Delimited key-value pairs
    
    Keyword arguments:
    delimiter -- delimiter that seperates key-value pairs. Default ';'

    Return:
    Dictionary form of the value.
    """

    stat_dict = {}
    stat_param = itertools.imap(lambda sp: info_to_tuple(sp, '='),
                                info_to_list(value, delimiter))
    for g in itertools.groupby(stat_param, lambda x: x[0]):
        try:
            value = map(lambda v: v[1], g[1])
            value = ','.join(sorted(value)) if len(value) > 1 else value[0]
            stat_dict[g[0]] = value
        except:
            # NOTE: 3.0 had a bug in stats at least prior to 3.0.44. This will
            # ignore that bug.
            pass
    return stat_dict


def info_colon_to_dict(value):
    """
    Simple function to convert colon separated string to dict
    
    Arguments:
    value -- Colon delimited key-value pairs

    Return:
    Dictionary form of the value.
    """
    return info_to_dict(value, ':')


def info_to_list(value, delimiter=';'):
    """
    Converts an info response to a list.

    Arguments:
    value -- Delimited values

    Keyword arguments:
    delimiter -- Delimiter seperating values. Default ';'

    Return:
    List containing the values.
    """
    return re.split(delimiter, value)


def info_to_tuple(value, delimiter=':'):
    """
    Converts an info response to a tuple.
    
    Arguments:
    value -- Delimited values

    Keyword arguments:
    delimiter -- Delimiter seperating values. Default ':'

    Return:
    Tuple containing the values.
    """
    return tuple(info_to_list(value, delimiter))


def concurrent_map(func, data):
    """
    Similar to the builtin function map(). But spawn a thread for each argument
    and apply 'func' concurrently.

    Note: unlike map(), we cannot take an iterable argument. 'data' should be an
    indexable sequence.

    Arguments:
    func -- funtion to map on
    data -- list of arguments to be passed to each function call.

    Return:
    List of values, with length of "data", returned by each call to func.
    """

    N = len(data)
    result = [None] * N

    #wrapper to dispose the result in the right slot
    def task_wrapper(i):
        result[i] = func(data[i])

    threads = [threading.Thread(target=task_wrapper, args=(i,)) for i in xrange(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return result


class cached(object):
    """
    Decorator that will cached results of a function call for a specified
    time to live.
    """
    def __init__(self, func, ttl=0.25):
        self.func = func
        self.ttl = ttl
        self.cache = {}

    def __setitem__(self, key, value):
        self.cache[key] = (value, time() + self.ttl)

    def __getitem__(self, key):
        if key in self.cache:
            value, eol = self.cache[key]
            if eol > time():
                return value
        
        self[key] = self.func(*key)
        return self.cache[key][0]

    def __call__(self, *args):
        return self[args]

logging = True

def log(module, *args, **kwargs):
    """
    Prints a colon delimited log message prfixed with unix epoch time,
    module name, and caller_name.
    
    Arguments:
    module -- Name of the module that called the log method.
    *args  -- List of arguments to be in a colon delimited log line.

    Keword arguments:
    stack_index -- Index on the stack of the function that called log.
    """
    if logging == False:
        return

    stack_index = 1 if not 'stack_index' in kwargs else kwargs['stack_index']

    caller_name = inspect.stack()[stack_index][3]
    line = ["%0.4f"%(time())
            , module
            , caller_name]
    line.extend(args)
    print ': '.join(map(str, line))
    sys.stdout.flush()        


def fqdn_to_ip(fqdn):
    """
    Converts an ip or fqdn to an ip.
    
    Arguments:
    fqdn -- FQDN address or IP of a host.

    Return:
    IP address of the host.
    """
    return socket.gethostbyname(fqdn)

def merge_dict(*args):
    return reduce(lambda x, y: 
                  dict(itertools.chain(x.iteritems(), y.iteritems()))
                  , args)
