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