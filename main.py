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
    output_dictionary = scan_hosts(list_of_hosts)
    print(output_dictionary)

    jsonResult = json.dumps(output_dictionary, indent=4)
    # json.dump(output_dictionary, output_file)
    output_file.write(jsonResult)
    output_file.close()

def scan_hosts(list_of_hosts):
    
    scan_output = []
    ssl_scanner = SSLScanner()
    nmap_scanner = NmapScanner()

    for host_to_be_scanned in list_of_hosts:
        scan_results = {}

        print(host_to_be_scanned)
        ssl_scanner.set_link(host_to_be_scanned)
        nmap_scanner.set_link(host_to_be_scanned)

        scan_results = nmap_scanner.perform_scans()

        for port in scan_results['ports']:
            ssl_scanner.set_port(port)
            ssl_result = ssl_scanner.perform_scans()
            scan_results['ports'][port] = ssl_result
        print(" scan results ")
        print (scan_results)

        output_dictionary = {"id": host_to_be_scanned}
        output_dictionary.update(scan_results)
        print(" output dictionary ")
        print(output_dictionary)
        scan_output.append(output_dictionary)
    print(" scan output ")
    print(scan_output)
    return scan_output
main()