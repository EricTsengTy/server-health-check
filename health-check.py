#!/usr/bin/env python3
import argparse
import yaml
import nmap
import dns
import dns.resolver
import subprocess

CONFIG_FILE = 'checklist.yaml'
DESCRIPTION = 'A script for health checking of machines'
EPILOG = 'Check for DNS lookup, IP & host pinging, port status'
TITLE = 'Diagnosis'

# Class for perform a test on a network with hostname, IP, ports specified
class Network:
    portscanner = nmap.PortScanner()
    resolver = dns.resolver.Resolver()
    def __init__(self, sname, info):
        self.sname = sname      # Service name
        self.hostname = self._get(info, 'hostname')
        self.IP = self._get(info, 'IP')
        self.valid_port = set(self._getports(self._get(info, 'valid-port', '')))
        self.block_port = set(self._getports(self._get(info, 'block-port', '')))
        if self.IP is None:
            self._err(f'Please specify IP address')
            raise
        self.success = True
        self.valid_err = [] # int
        self.block_err = [] # int

    # Test fully
    def fulltest(self, scan_popular=False):
        self.pingtest()
        self.portscan()
        if scan_popular: 
            self.scanpopular()
        self.dnstest()
        self.valid_err.sort()
        self.block_err.sort()
        if self.valid_err: self._err(f'{self.IP} port closed: {", ".join(map(str, self.valid_err))}')
        if self.block_err: self._err(f'{self.IP} port open: {", ".join(map(str, self.block_err))}')
        if self.success: self._win(f'{self.IP} is healthy')
        return self.success

    # Try to ping the hostname and the IP 
    def pingtest(self):
        if not self._pingtest(self.hostname):
            self._err(f'Ping {self.hostname} failed')
        if not self._pingtest(self.IP):
            self._err(f'Ping {self.IP} failed')
        return self.success

    # Scan ports and check the status (open or closed (or filtered))
    def portscan(self):
        self._portscan(self.valid_port, True)
        self._portscan(self.block_port, False)
        return self.success

    # Compare the resolved IP from the hostname with the IP specified
    def dnstest(self):
        resolver = Network.resolver
        try:
            res = resolver.resolve(self.hostname)
        except dns.resolver.NXDOMAIN:
            self._err(f'The DNS query name does not exist: {self.hostname}')
            return self.success
        
        # TODO: Deal with multiple IPs
        resolvedIP = res[0].to_text()
        if resolvedIP != self.IP:
            self._err(f'IP of DNS query mismatch ({resolvedIP} != {self.IP})')
        return self.success

    # Scan the most popular 1000 ports
    def scanpopular(self):
        portscanner = Network.portscanner
        res = portscanner.scan(self.IP, arguments='')
        if self.IP not in res['scan']: 
            return
        for port, info in res['scan'][self.IP]['tcp'].items():
            if info['state'] == 'open' and port not in self.valid_port and port not in self.block_port:
                self.block_err.append(port)


    # Ping by "ping -c 1 {target}" and return True if the target responds
    def _pingtest(self, target):
        proc = subprocess.Popen(['ping', '-c', '1', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        return proc.returncode == 0

    # Scan by "nmap -p {port} {IP}"
    def _portscan(self, portsList, stat):
        portscanner = Network.portscanner
        # portsList = self._getports(portsList)
        for port in portsList:
            res = portscanner.scan(self.IP, arguments=f'-p {port}')  # nmap -p {port} {IP}
            if self.IP not in res['scan']:                           # Host might be down    
                continue                  
            res = True if res['scan'][self.IP]['tcp'][port]['state'] == 'open' else False
            if res is not stat:
                # self._err(f"Port {port} of {self.IP} is {'open' if res else 'closed'}")
                if stat: self.valid_err.append(port)
                else: self.block_err.append(port)

    # Str to list (e.g. "2,3-5,9,10" --> [2, 3, 4, 5, 9, 10])
    def _getports(self, portsList):
        portsList = filter(None, str(portsList).split(','))
        res = []
        for ports in portsList:
            ports = ports.split('-')
            ports.append(ports[0])
            for port in range(int(ports[0]), int(ports[1]) + 1):
                res.append(port)
        return res


    def _get(self, d, key, default=None):
        return d[key] if d.get(key) is not None else default

    # Print error message
    def _err(self, message):
        prefix = f'{self.sname}:'.ljust((len(self.sname) + 9) // 8 * 8)
        print(f'\u2718 {prefix}{message}')
        self.success = False
    
    def _win(self, message):
        prefix = f'{self.sname}:'.ljust((len(self.sname) + 9) // 8 * 8)
        print(f'\u2714 {prefix}{message}')

# Just a service with some networks
class Service:
    def __init__(self, name, info):
        self.name = name
        self.public = Network(name, info['Public']) if info.get('Public') is not None else None
        self.private = Network(name, info['Private']) if info.get('Private') is not None else None

    def test(self, scan_popular=False):
        if self.public is not None: self.public.fulltest(scan_popular=scan_popular)
        if self.private is not None: self.private.fulltest(scan_popular=scan_popular)
        return (self.public is None or self.public.success) \
                and (self.private is None or self.private.success)

# Print text in a box
def boxing(text: str):
    text = ' ' + text + ' '
    print('\u256d' + '\u2500' * len(text) + '\u256e')
    print('\u2502' + text + '\u2502')
    print('\u2570' + '\u2500' * len(text) + '\u256f')

if __name__ == '__main__':
    # Load the arguments
    argparser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG)
    argparser.add_argument('-f', metavar='FILE', action='store', default=CONFIG_FILE, type=str, help=f'specify path of config file (default: {CONFIG_FILE})')
    argparser.add_argument('--service', metavar='s1,s2,...', action='store', help=f'check specific services in the config')
    argparser.add_argument('--scan-popular', action='store_true', help=f'also scan the most popular 1000 ports')
    args = argparser.parse_args()
    CONFIG_FILE = args.f

    # Load config
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    
    # Print title
    boxing(TITLE)

    # Get services (check only specific services if mention in --service)
    services = [] if config is None else [ Service(key, info) for key, info in config.items() ]
    if args.service:
        services = [ Service(key, config[key]) for key in args.service.split(',') if key ]
    
    # Testing
    for idx, service in enumerate(services):
        service.test(args.scan_popular)