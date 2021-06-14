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

## Scan specific services with a config specified
$ ./health-check.py -f mylist.yaml --service=webserver,dnsserver

## Scan mailserver with top 1000 ports (defined by nmap)
$ ./health-check.py --service=mailserver --scan-popular
```

## Configure example
```vim
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