#Note:

The previous implementation of the nagios plugin has been moved to the
`legacy` branch.


#Introduction

aerospike\_nagios.py simplifies nagios configurations for Aerospike clusters.
The goal is to reduce the complexity to 2 simple steps.

1. Copy aerospike\_nagios.py and dependencies to your Nagios server
2. Add aerospike configs into Nagios

#Features

- Can monitor any stat returned by
  - `$ asinfo -v 'statistics' [-h host]`
  - `$ asinfo -v 'namespace/<NAMESPACE NAME>' [-h host]`
  - `$ asinfo -v 'dc/<DATACENTER>' [-h host]`
  - `$ asinfo -v 'latency:hist=<LATCENCY STAT>' [-h host]`

### Requirements

See requirements.txt.

```
sudo pip install -r requirements.txt
```

### Getting Started

1. Copy aerospike\_nagios.py to your prefered scripts dir

    > Eg: /opt/aerospike/bin/

1. Copy aerospike\_schema.yaml and ssl\_context.py to the same directory

1. Copy examples/aerospike.cfg into your nagios conf.d directory

   > /etc/nagios/conf.d if installed from repo  
   > /usr/local/nagios/etc/objects if installed from source

1. Edit aerospike.cfg to add your aerospike hosts into the hostgroup

1. Restart/reload nagios


### Aerospike nagios Plugin

See *aerospike\_nagios.py*, this is the file that nagios will schedule to perform
queries against Aerospike. Other than copying it to the appropriate location,
you are not required to interact with it.

###  Usage
```bash
usage: aerospike_nagios.py [-u] [-U USER] [-P [PASSWORD]] [-v]
                           [-n NAMESPACE | -l LATENCY | -x DC] -s STAT
                           [-p PORT] [-h HOST] -c CRIT -w WARN [--tls_enable]
                           [--tls_encrypt_only] [--tls_keyfile TLS_KEYFILE]
                           [--tls_certfile TLS_CERTFILE]
                           [--tls_cafile TLS_CAFILE] [--tls_capath TLS_CAPATH]
                           [--tls_protocols TLS_PROTOCOLS]
                           [--tls_blacklist TLS_BLACKLIST]
                           [--tls_ciphers TLS_CIPHERS] [--tls_crl]
                           [--tls_crlall] [--tls_name TLS_NAME]

optional arguments:
  -u, --usage, --help   Show this help message and exit
  -U USER, --user USER  user name
  -P [PASSWORD], --password [PASSWORD]
                        password
  -v, --verbose         Enable verbose logging
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace name. eg: bar
  -l LATENCY, --latency LATENCY
                        Options: see output of asinfo -v 'latency:hist' -l
  -x DC, --xdr DC       Datacenter name. eg: myDC1
  -s STAT, --stat STAT  Statistic name. eg: cluster_size
  -p PORT, ---port PORT
                        PORT for Aerospike server (default: 3000)
  -h HOST, --host HOST  HOST for Aerospike server (default: 127.0.0.1)
  -c CRIT, --critical CRIT
                        Critical level
  -w WARN, --warning WARN
                        Warning level
  --tls_enable          Enable TLS
  --tls_encrypt_only    TLS Encrypt Only
  --tls_keyfile TLS_KEYFILE
                        The private keyfile for your client TLS Cert
  --tls_certfile TLS_CERTFILE
                        The client TLS cert
  --tls_cafile TLS_CAFILE
                        The CA for the server's certificate
  --tls_capath TLS_CAPATH
                        The path to a directory containing CA certs and/or
                        CRLs
  --tls_protocols TLS_PROTOCOLS
                        The TLS protocol to use. Available choices: SSLv2,
                        SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or
                        - can be appended before the protocol to indicate
                        specific inclusion or exclusion.
  --tls_blacklist TLS_BLACKLIST
                        Blacklist including serial number of certs to revoke
  --tls_ciphers TLS_CIPHERS
                        Ciphers to include. See https://www.openssl.org/docs/m
                        an1.0.1/apps/ciphers.html for cipher list format
  --tls_crl             Checks SSL/TLS certs against vendor's Certificate
                        Revocation Lists for revoked certificates. CRLs are
                        found in path specified by --tls_capath. Checks the
                        leaf certificates only
  --tls_crlall          Check on all entries within the CRL chain
  --tls_name TLS_NAME   The expected name on the server side certificate
```

To monitor a specific general statistic:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -w WARN_LEVEL -c CRIT_LEVEL`

To monitor a specific statistic in a namepsace:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -n YOUR_NAMESPACE -w WARN_LEVEL -c CRIT_LEVEL`

To monitor a specfic statistic in xdr:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -x DATACENTER -w WARN_LEVEL -c CRIT_LEVEL`

To monitor latency statistics (pre-3.9):  
`aerospike_nagios.py -h YOUR_ASD_HOST -s <1ms|8ms|64ms>  -l <reads|writes|writes_reply|proxy> -w WARN_LEVEL -c CRIT_LEVEL`

To monitor latency statistics (ASD 3.9+):
`aerospike_nagios.py -h YOUR_ASD_HOST -s <1ms|8ms|64ms>  -l {NAMESPACE}-<read|write|proxy|udf> -w WARN_LEVEL -c CRIT_LEVEL`
eg:
`aerospike_nagios.py -h localhost -s 1ms  -l {test}-read -w 8 -c 10`

To utilize encrypt only:
`aerospike_nagios.py -h YOUR_ASD_HOST -p YOUR_SECURED_PORT -s STAT_NAME --tls_enabled --tls_encrypt_only -w WARN_LEVEL -c CRIT_LEVEL`

To utilize SSL/TLS standard auth:
`aerospike_nagios.py -h YOUR_ASD_HOST -p YOUR_SECURED_PORT -s STAT_NAME --tls_enabled --tls_cafile YOUR_CA_PEM --tls_name YOUR_ASD_CERT_NAME -w WARN_LEVEL -c CRIT_LEVEL`

### Alert Levels

Warning and Critical thresholds are specified according to [Nagios' format](https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT)

To not use warning and/or critical levels, set them to 0.

Example usage can be found in the examples/aerospike.cfg file. 
