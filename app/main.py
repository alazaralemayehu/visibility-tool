import json
import logging
import time
import subprocess
import boto3
from botocore.exceptions import ClientError
import os
from NmapScanner import NmapScanner
from SSLScanner import SSLScanner
import boto3

def main(event=None, context=None):
    links_file = open("links.txt", "r")
    list_of_hosts = []
    
    # output file name that saves the json output
    file_name = "result" + time.strftime("%Y%m%d-%H%M%S") + ".json"
    output_file = open(file_name, "a")
    output_dictionary = {}

    for line in links_file.readlines():
        list_of_hosts.append(line.strip())

    print(subprocess.check_output([ "whoami"]))

    output_dictionary = scan_hosts(list_of_hosts)
    print(output_dictionary)

    json_result = json.dumps(output_dictionary, indent=4)
    # json.dump(output_dictionary, output_file)
    output_file.write(json_result)
    output_file.close()

    response = upload_file(file_name, '')
    print(response)

def upload_file (file_name, bucket):

    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, file_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True

def scan_hosts(list_of_hosts):
    
    scan_output = []
    ssl_scanner = SSLScanner()
    nmap_scanner = NmapScanner()

    for host_to_be_scanned in list_of_hosts:
        print("scanning " + host_to_be_scanned)
        scan_results = {}

        ssl_scanner.set_link(host_to_be_scanned)
        nmap_scanner.set_link(host_to_be_scanned)

        scan_results = nmap_scanner.perform_scans()
        if (scan_results is None):
            continue

        for port in scan_results['ports']:
            ssl_result = {}
            if (int(port) == 443):
                ssl_scanner.set_port(port)
                ssl_result = ssl_scanner.perform_scans()
            scan_results['ports'][port] = ssl_result

        output_dictionary = {"id": host_to_be_scanned}
        output_dictionary.update(scan_results)
        scan_output.append(output_dictionary)
    return scan_output
main()