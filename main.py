import json
import time
import subprocess
from NmapScanner import NmapScanner
from SSLScanner import SSLScanner

def main(event=None, context=None):
    linksFile = open("links.txt", "r")
    list_of_hosts = []
    
    file_name = "result" + time.strftime("%Y%m%d-%H%M%S") + ".json"
    output_file = open(file_name, "a")
    output_dictionary = {}

    for line in linksFile.readlines():
        list_of_hosts.append(line.strip())

    print(subprocess.check_output([ "whoami"]))

    output_dictionary ={}
    ssl_scanner = SSLScanner()
    nmap_scanner = NmapScanner()

    for host_to_be_scanned in list_of_hosts:
        scan_results = {}
        
        print(host_to_be_scanned)
        ssl_scanner.set_link(host_to_be_scanned)
        nmap_scanner.set_link(host_to_be_scanned)

        nmap_result = nmap_scanner.perform_scans()
        scan_results['nmap_results'] = nmap_result

        ssl_result = ssl_scanner.perform_scans()
        scan_results['ssl_results'] = ssl_result

        output_dictionary[host_to_be_scanned] = scan_results


    jsonResult = json.dumps(output_dictionary, indent=4)
    json.dump(output_dictionary, output_file)

    print(jsonResult)
    output_file.close()

main()