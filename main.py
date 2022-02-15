from doctest import OutputChecker
import string
import json
import time
import subprocess
from NmapScanner import NmapScanner

from SSLScanner import SSLScanner

def main(event=None, context=None):
    linksFile = open("links.txt", "r")
    listOfHosts = []

    for line in linksFile.readlines():
        listOfHosts.append(line.strip())

    print(subprocess.check_output([ "whoami"]))
    output_dictionary ={}
    ssl_scanner = SSLScanner()
    nmap_scanner = NmapScanner()

    for host_to_be_scanned in listOfHosts:
        scanResult: dict = {}


    jsonResult = json.dumps(outputDictionary, indent=4)
    json.dump(outputDictionary, outPutFile)

    print(jsonResult)

    outPutFile.close()


def performOSDetection(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-O")
    hosts = nm.all_hosts()
    results = []
    # print(scanned)
    for host in hosts:
        results.append(scanned['scan'][host]['osmatch'])
    if (len(results) > 0):
        if (len(results[0][0]> 0)):
            return (results[0][0]['name'])

    # print(type(results[0][0]))
    return results

def detectSSLVersion(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-sV --script ssl-enum-ciphers -p 443")
    # print(scanned)
    host = nm.all_hosts()[0]
    result:dict = scanned['scan'][host]['tcp']
    if (443 not in result.keys()):
        return result
    result = result[443]
    if ('script' not in result.keys()):
        return result

    result = result[443]['script']['ssl-enum-ciphers']
    # print(result, type(result))

    return result
    # result:dict = scanned['scan'][host]['tcp'][443]['script']['ssl-enum-ciphers']

    # return result

def performTCPPortScan (host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1024','-v -sS -sV')
    hosts = nm.all_hosts()
    results = {}
    keyToRemove = ['reason','product','version', 'extrainfo','conf','cpe']

    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                openPortsState = nm[host][proto][port]['state']
                openPortServiceName = nm[host][proto][port]['name']

                results[port] = [openPortsState, openPortServiceName]

                # result = str(port) + " : "+ str(nm[host][proto][port])

                # results.append(result)
                # print(port , " info ", nm[host][proto][port])
    # for i in results:
    #     print(i)
    # print(results)
    return (results)

def performComprehensiveScan(host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, arguments='-v -A')
    results = []
    hosts = nm.all_hosts()
    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                result = str(port) + " : "+ str(nm[host][proto][port])
                results.append(result)
                # print(port , " info ", nm[host][proto][port])
    print(result)
    return (results)

main()