# check_eigrp

version 0.1.0

> Copyright (C) 2014 [Tiunov Igor](mailto:igortiunov@gmail.com)
> SNMPv3 added by [Bryan Heden](mailto:b.heden@gmail.com)

Check status of EIGRP protocol and obtain neighbors count via SNMP

## Compilation and Installation

1. First, configure options
   ```
   ./configure
   ```
1. Then, compile the binary
   ```
   make all
   ```
1. Then copy your binary to your plugin directory
   ```
   cp src/check_eigrp /path/to/your/plugins
   ```

Altogether:

```
./configure
make all
cp src/check_eigrp /path/to/your/plugins
```

## Usage

Usage:

```
check_eigrp [-h] [-V] -H <hostipaddress> -p <protocol version> [-c <v3 context>] [-L <seclevel>] [-a <authproto>] [-x <privproto>] [-U <username>] [-A <authpasswd>] [-X <privpasswd>] [-C <community>] -s <EIGRP AS number> -n <neighbors> [-t <timeout>] [-v]
```


* `-h`, `--help`
   Show this help message
* `-V`, `--version`
   print the version of plugin
* `-H`, `--hostname=ADDRESS`
   specify the hostname of router
   you can specify a port number by this notation: "ADDRESS:PORT"
* `-p`, `--protocol=STRING`
   specify snmp version to use one of (`1|2c|3`)
   defaults to 2c
* `-c`, `--context=STRING`
   SNMPv3 context
* `-L`, `--seclevel=STRING`
   SNMPv3 security level: one of (`noAuthNoPriv|authNoPriv|authPriv`)
   defaults to noAuthNoPriv
* `-a`, `--authproto=STRING`
   SNMPv3 authentication protocol: one of (`md5|sha`)
   defaults to md5
* `-x`, `--privproto=STRING`
   SNMPv3 privacy protocol: one of (`des|aes`)
   defaults to des
* `-U`, `--secname=STRING`
   SNMPv3 username
* `-A`, `--authpasswd=STRING`
   SNMPv3 authentication password
* `-X`, `--privpasswd=STRING`
   SNMPv3 privacy password
* `-C`, `--community=STRING`
   specify the SNMP community of router
* `-s`, `--asnumber=INTEGER`
   specify the EIGRP AS number of router
* `-n`, `--neighbors=INTEGER`
   specify the neighbors count of router
* `-t`, `--timeout=INTEGER`
   specify the timeout of plugin,
   default is 3 sec, max 60 sec
* `-v`, `--verbose`
   specify this key if you need to get a
   list of neighbors (disabled by default).
