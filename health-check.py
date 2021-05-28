#!/usr/bin/env python3
import argparse
import yaml
import nmap
import dns
import dns.resolver
import subprocess

CONFIG_FILE = 'checklist.yaml'
DESCRIPTION = 'A script for health checking of machines'
TITLE = 'Diagnosis'

# Class for perform a test on a network with hostname, IP, ports specified
class Network:
    portscanner = nmap.PortScanner()
    resolver = dns.resolver.Resolver()
    def __init__(self, sname, info):
        self.sname = sname      # Service name
        self.hostname = self._get(info, 'hostname')
        self.IP = self._get(info, 'IP')
        self.valid_port = filter(None, str(self._get(info, 'valid-port', '')).split(','))
        self.block_port = filter(None, str(self._get(info, 'block-port', '')).split(','))
        if self.IP is None:
            self._err(f'Please specify IP address')
            raise
        self.success = True

    # Test fully
    def fulltest(self):
        self.pingtest()
        self.portscan()
        self.dnstest()
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
            res = resolver.query(self.hostname)
        except dns.resolver.NXDOMAIN:
            self._err(f'The DNS query name does not exist: {self.hostname}')
            return self.success
        
        # TODO: Deal with multiple IPs
        resolvedIP = res[0].to_text()
        if resolvedIP != self.IP:
            self._err(f'IP of DNS query mismatch ({resolvedIP} != {self.IP})')
        return self.success

    # Ping by "ping -c 1 {target}" and return True if the target responds
    def _pingtest(self, target):
        proc = subprocess.Popen(['ping', '-c', '1', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        return proc.returncode == 0

    # Scan by "nmap -p {port} {IP}"
    def _portscan(self, portsList, stat):
        portscanner = Network.portscanner
        for ports in portsList:
            ports = ports.split('-')
            ports.append(ports[0])
            for port in range(int(ports[0]), int(ports[1]) + 1):
                res = portscanner.scan(self.IP, arguments=f'-p {port}')  # nmap -p {port} {IP}
                res = True if res['scan'][self.IP]['tcp'][port]['state'] == 'open' else False
                if res is not stat:
                    self._err(f"Port {port} of {self.IP} is {'open' if res else 'closed'}")


    def _get(self, d, key, default=None):
        return d[key] if d.get(key) is not None else default

    # Print error message
    def _err(self, message):
        prefix = f'{self.sname}:'.ljust((len(self.sname) + 9) // 8 * 8)
        print(f'{prefix}{message}')
        self.success = False

# Just a service with some networks
class Service:
    def __init__(self, name, info):
        self.name = name
        self.public = Network(name, info['Public']) if info.get('Public') is not None else None
        self.private = Network(name, info['Private']) if info.get('Private') is not None else None

    def test(self):
        if self.public is not None: self.public.fulltest()
        if self.private is not None: self.private.fulltest()
        return self.public.success and self.private.success

def boxing(text: str):
    text = ' ' + text + ' '
    print('\u2554' + '\u2550' * len(text) + '\u2557')
    print('\u2551' + text + '\u2551')
    print('\u255a' + '\u2550' * len(text) + '\u255d')

def boxing(text: str):
    text = ' ' + text + ' '
    print('\u256d' + '\u2500' * len(text) + '\u256e')
    print('\u2502' + text + '\u2502')
    print('\u2570' + '\u2500' * len(text) + '\u256f')

if __name__ == '__main__':
    # Load the arguments
    argparser = argparse.ArgumentParser(description=DESCRIPTION)
    argparser.add_argument('-f', metavar='FILE', action='store', default=CONFIG_FILE, type=str, help=f'specify path of config file (default: {CONFIG_FILE})')
    args = argparser.parse_args()
    CONFIG_FILE = args.f

    # Load config
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    # Testing
    services = [ Service(key, info) for key, info in config.items() ]
    boxing(TITLE)
    for idx, service in enumerate(services):
        if not service.test():
            print('\u2500' * (len(TITLE) + 4))