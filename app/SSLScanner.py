import subprocess
import re

class SSLScanner:
    def __init__(self) -> None:
        self.link = None
        self.port = 443

    def set_link(self, link):
        self.link = link

    def set_port(self, port):
        self.port = port

    def perform_scans(self):
        # for link in self.links:
        sub_process_result = subprocess.check_output(["./sslscan/sslscan",  self.link +":"+str(self.port)],  universal_newlines=True)
        escaped_result = self.ansi_code_remover(sub_process_result)
        result = self.extract_scanner_report(escaped_result.split("\n"))
        return (result)
        

    def extract_tls_protocol(self,list_of_results, startIndex, endIndex):
        results = {}
        for i in range(startIndex+1, endIndex):
            protocol = list_of_results[i].split()
            if (len(protocol) == 0):
                continue
            if (protocol[1] not in results.keys()):
                results[protocol[1]] = [protocol[0]]
            else:
                results[protocol[1]].append(protocol[0])
        return (results)

    def extract_supported_cipher(self, list_of_results, startIndex, endIndex):
        supported_cipher = {}
        for i in range(startIndex+1, endIndex):
            protocol = list_of_results[i].split()
            if (len(protocol) == 0):
                continue

            property = protocol[0]
            value = " ".join(protocol[1:])
            if (property not in ["Preferred", "Accepted"]):
                return []

            if (property not in supported_cipher.keys()):
                supported_cipher[property] = [value]

            else:
                supported_cipher[property].append(value)
        return (supported_cipher)

    def extract_heart_bleed(self,list_of_results, startIndex, endIndex):

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

    def get_next_key (self,dictionary: dict, current_key: str) -> str:
        dictionary_list = list(dictionary)
        try:
            new_key = dictionary_list[dictionary_list.index(current_key) + 1]
            return str(new_key)
        except Exception as e:
            return None    
    
    def get_indexes(self, property_dictionary:dict,  current_key: str, length:int):
        try:
            if (current_key in property_dictionary):
                next_key = self.get_next_key(property_dictionary, current_key)

                last_index = None
                if (next_key is None):
                    last_index = length -1
                else:
                    last_index = property_dictionary[next_key]
                return [property_dictionary[current_key], last_index]
        except Exception as e:
            print(" debugging")
        return None, None

    def extract_scanner_report(self, result):

        required_properties = ["SSL/TLS Protocols:","TLS renegotiation:","TLS Fallback SCSV:","TLS Compression:","Heartbleed:","Supported Server Cipher(s):", "Server Key Exchange Group(s):","SSL Certificate:"]
        result = [line.strip() for line in result]

        property_dictionary = {}
        ssl_information={}
        for required_property in required_properties:
            if (required_property in result):
                property_dictionary[required_property] = result.index(required_property)

        property_dictionary = dict(sorted(property_dictionary.items(), key=lambda item:item[1]))
        try:
            current_key = required_properties[0]
            first_index, last_index = self.get_indexes(property_dictionary, current_key, len(result))
            if (not(first_index is None or last_index is None)):
                ssl_information["ssl_protocol"] = self.extract_tls_protocol(result, first_index, last_index)
            
            current_key = required_properties[4]
            first_index, last_index = self.get_indexes(property_dictionary, current_key, len(result))
            
            if (not(first_index is None or last_index is None)):
                ssl_information["heart_bleed_info" ] = self.extract_heart_bleed(result, first_index, last_index)
            
            current_key = required_properties[5]
            first_index, last_index = self.get_indexes(property_dictionary, current_key, len(result))
            if (not(first_index is None or last_index is None)):
                ssl_information["supported_cipher"]= self.extract_supported_cipher(result, first_index, last_index)

                
        except (ValueError, IndexError):
            print(" something is wrong")
    
        return ssl_information
