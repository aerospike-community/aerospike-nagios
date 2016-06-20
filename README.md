#Note:

The previous implementation of the nagios plugin has been moved to the
`legacy` branch.


#Introduction

aerospike\_nagios.py simplifies nagios configurations for Aerospike clusters.
The goal is to reduce the complexity to 2 simple steps.

1. Copy aerospike\_nagios.py to your Nagios server
2. Add aerospike configs into Nagios

#Features

- Can monitor any stat returned by
  - `$ asinfo -v 'statistics' [-h host]`
  - `$ asinfo -v 'namespace/<NAMESPACE NAME>' [-h host]`
  - `$ asinfo -v 'dc/<DATACENTER>' [-h host]`
  - `$ asinfo -v 'latency:hist=<LATCENCY STAT>' [-h host]`

###Known Issues

- Host based monitoring instead of cluster based monitoring

### Requirements

1. Aerospike python client. See [this page](http://www.aerospike.com/docs/client/python/install/)

### Getting Started

1. Copy aerospike\_nagios.py to your prefered scripts dir

    > Eg: /opt/aerospike/bin/

1. Copy aerospike\_schema.yaml to the same directory

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

    Usage:
     -h host (default 127.0.0.1)
     -p port (default 3000)
     -U user (Enterprise only)
     -P password (Enterprise only)
     -x xdr datacenter (Enterprise 3.8+)
     -s "statistic" (Eg: "free-pct-memory")
     -n "namespace" (Eg: "namespace/test")
     -l "latency" (Options: reads, writes, writes_reply, proxy) 
     -c "critical level" (Eg: "60")
     -w "warning level" (Eg: "70")

To monitor a specific general statistic:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -w WARN_LEVEL -c CRIT_LEVEL`

To monitor a specific statistic in a namepsace:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -n YOUR_NAMESPACE -w WARN_LEVEL -c CRIT_LEVEL`

To monitor a specfic statistic in xdr:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s STAT_NAME -x DATACENTER -w WARN_LEVEL -c CRIT_LEVEL`

To monitor latency statistics:  
`aerospike_nagios.py -h YOUR_ASD_HOST -s <1ms|8ms|64ms>  -l <reads|writes|writes_reply|proxy> -w WARN_LEVEL -c CRIT_LEVEL`

### Alert Levels

Warning and Critical thresholds are specified according to [Nagios' format](https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT)

To not use warning and/or critical levels, set them to 0.

Example usage can be found in the examples/aerospike.cfg file. 
