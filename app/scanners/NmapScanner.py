import nmap
import dns.resolver

class NmapScanner:
    
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        self.link = None

    def set_link(self, link):
        self.link = link

    def perform_scans(self):
        scan_result = {}
        host_to_be_scanned = self.link
        if (not self.is_host_up(host_to_be_scanned)):
            return None

        ports = self.perform_TCP_port_scan(host_to_be_scanned)
        scan_result['ports'] = ports

        return (scan_result)
    def is_host_up (self, host_to_scan):
        try:
            answers = dns.resolver.resolve(host_to_scan,'A')
            answers = list(answers)
            if (len(answers) > 0):
                return True
        except Exception as ex:
            print(ex)
            return False 

    def perform_TCP_port_scan(self, host_to_scan):
        self.nm.scan(host_to_scan) #'-sV -sS -T4 -v')  '1-65535',
        hosts = self.nm.all_hosts()
        results = {}
        for host in hosts:
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    open_port_state = self.nm[host][proto][port]['state']
                    open_port_service_name = self.nm[host][proto][port]['name']
                    results[port] = {'status' :[open_port_state, open_port_service_name]}
        return (results)
    
    def perform_OS_scan(self, host_to_scan):
        scanned = self.nm.scan(host_to_scan, arguments="-O")
        hosts = self.nm.all_hosts()
        results = []
        for host in hosts:
            results.append(scanned['scan'][host]['osmatch'])
        if (len(results) > 0):
            if (len(results[0]) > 0):
                return (results[0][0]['name'])

        return results
