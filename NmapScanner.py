import nmap

class NmapScanner:
    
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        self.link = None

    def set_link(self, link):
        self.link = link

    def perform_scans(self):
        scan_result = {}
        # for host_to_be_scanned in self.links:
        host_to_be_scanned = self.link
        ports = self.perform_TCP_port_scan(host_to_be_scanned)
        scan_result['ports'] = ports
        # os_scan = self.perform_OS_scan(host_to_be_scanned)
        # scan_result['os'] = os_scan

        return (scan_result)

    def perform_TCP_port_scan(self, host_to_scan):
        self.nm.scan(host_to_scan, '1-1024','-v -sS -sV')
        hosts = self.nm.all_hosts()
        results = {}
        for host in hosts:
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    openPortsState = self.nm[host][proto][port]['state']
                    openPortServiceName = self.nm[host][proto][port]['name']
                    results[port] = {'status' :[openPortsState, openPortServiceName]}
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
