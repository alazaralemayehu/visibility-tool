import subprocess
import re

class SSLScanner:
    def __init__(self) -> None:
        self.link = None

    def set_link(self, link):
        self.link = link

    def perform_scan(self):
        # for link in self.links:
        sub_process_result = subprocess.check_output(["sslscan", self.link],  universal_newlines=True)
        escaped_result = self.ansi_code_remover(sub_process_result)
        result = self.extract_scanner_report(escaped_result.split("\n"))

        print(result)
        

    def extract_tls_protocol(self,list_of_results, startIndex, endIndex):
        results = []
        for i in range(startIndex+1, endIndex):
            protocol = list_of_results[i].split()
            if (len(protocol) == 0):
                continue
            results.append({protocol[0]: protocol[1]})
            
        return (results)

    def extract_supported_cipher(self, list_of_results, startIndex, endIndex):
        suported_cipher = {}
        for i in range(startIndex+1, endIndex):
            protocol = list_of_results[i].split()
            if (len(protocol) == 0):
                continue

            property = protocol[0]
            value = " ".join(protocol[1:])
            if (property not in suported_cipher.keys()):
                suported_cipher[property] = [value]
            else:
                suported_cipher[property].append(value)
        return (suported_cipher)

    def extract_heard_bleed(self,list_of_results, startIndex, endIndex):

        heart_bleed_result = {}
        results = []
        for i in range(startIndex+1, endIndex):
            protocol = list_of_results[i].split()
            if (len(protocol) == 0):
                continue
            property = protocol[0]
            value = ' '.join(protocol[1:])

            results.append({protocol[0]:value})
        
        heart_bleed_result[list_of_results[startIndex]] = results
        return (results)
    
    def ansi_code_remover(self, line):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        escaped_string = ansi_escape.sub('', line)
        return escaped_string

    def extract_scanner_report(self, result):

        required_strings = ["SSL/TLS Protocols:","TLS Fallback SCSV:","TLS renegotiation:","TLS Compression:","Heartbleed:","Supported Server Cipher(s):","Server Key Exchange Group(s):","SSL Certificate:"]
        result = [line.strip() for line in result]
     
        property_dictionary = {i: result.index(i) for i in required_strings}
        print(property_dictionary)

        ssl_protocols = self.extract_tls_protocol(result, property_dictionary[required_strings[0]], property_dictionary[required_strings[1]])
        heart_bleed_info = self.extract_heard_bleed(result, property_dictionary[required_strings[4]], property_dictionary[required_strings[5]])
        supported_cipher = self.extract_supported_cipher(result, property_dictionary[required_strings[5]], property_dictionary[required_strings[6]])

        ssl_information ={
            "ssl_protocol" : ssl_protocols,
            "heard_bleed_info" : heart_bleed_info,
            "supported_cipher" : supported_cipher
        }
        return  ssl_information


ssl = SSLScanner()
ssl.set_link("electrification.dev.pki.dps.kone.com")
ssl.perform_scan()