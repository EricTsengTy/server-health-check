# Server Health Check
## Install
```shell
## Install nmap
$ sudo apt update
$ sudo apt install nmap

## Install required python packages
$ pip3 install -r requirements.txt
```

## Usage
```shell
## Help message
$ ./health-check.py -h

usage: health-check.py [-h] [-f FILE] [--service s1,s2,...] [--scan-popular]

A script for health checking of machines

optional arguments:
  -h, --help           show this help message and exit
  -f FILE              specify path of config file (default: checklist.yaml)
  --service s1,s2,...  check specific services in the config
  --scan-popular       also scan the most popular 1000 ports

Check for DNS lookup, IP & host pinging, port status

## Scan specific services with a config specified
$ ./health-check.py -f mylist.yaml --service=webserver,dnsserver

## Scan mailserver with top 1000 ports (defined by nmap)
$ ./health-check.py --service=mailserver --scan-popular
```

## Example config
```yaml
webserver:
    Public:
        hostname: web1.example.com
        IP: 93.184.216.34
        valid-port: 22
        block-port: 80-88,8080

dnsserver:
    Public:
        hostname: dns1.example.com
        IP: 93.184.216.33
        valid-port: 53
        block-port: 80
    Private:
        hostname: dns1.priv.example.com
        IP: 10.112.216.33
        valid-port: 22,53
```