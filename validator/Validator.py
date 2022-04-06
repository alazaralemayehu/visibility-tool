
import argparse
import json
import os

# https://www.dnspython.org/examples/
class RuleManager: 
    def __init__(self) -> None:
        self.rules = None
        self.rules_file = None
        self.is_valid_rule = False
    
    def set_rules_file(self, file_name):
        self.rules_file = file_name
    
    def set_rules(self,rules):
        self.rules = rules

    def get_rules(self):
        return self.rules

    def validate_rule_structure(self):
        if (self.rules == None and self.rules_file == None):
            print("Unable to find json file or json object to validate")
            self.is_valid_rule = False
            return False
       
        elif (self.rules == None and self.rules_file != None):
            f = open(self.rules_file, "r")
            json_string = f.read()
            json_objects = json.loads(json_string)
            self.rules = json_objects
        try:
            rules = self.rules['rules']
            rule_identifiers = [rule['name'] for rule in rules]
            applied_rules = self.rules['applied_rules']

            undefined_rules = []
        
            for applied_rule in applied_rules:
                for enforced_rule in applied_rule['enforced_rules']:
                    if (enforced_rule not in rule_identifiers):
                        undefined_rules.append(enforced_rule)

            if (len(undefined_rules) != 0):
                print("The following rules are not defined")
                for undefined_rule in undefined_rules:
                    print (undefined_rule)  
                self.is_valid_rule = False
                return False

            self.is_valid_rule = True
            return True  

        except KeyError as e:
            print("Key "+ e.args[0] +" is required as list")
            self.is_valid_rule = False
            return False


class ResourceManager:
    def __init__(self) -> None:
        self.resource_file = None
        self.resources = None
        self.is_valid_resource = False
        self.aggregated_resource_list = []

    def set_resource(self, resources :dict):
        self.resources = resources
    
    def set_resource_files (self, resources_file_name: str):
        self.resource_file = resources_file_name

    def get_resource_properties(self):
        if (self.resource_file == None and self.resources == None):
            print("Unable to find json file or json object to validate")
            return False
       
        elif (self.resources == None and self.resource_file != None):
            f = open(self.resource_file, "r")
            json_string = f.read()
            json_objects = json.loads(json_string)
            self.resources = json_objects

        self.is_valid_resource = True
        for index in range(len(self.resources)):

            resource_id= self.extract_id(index)
            resource_open_ports = self.extract_open_ports(index) 
            enabled_ssl_version = self.extract_enabled_ssl_version(resource_open_ports, index)
            
            aggregated_result =  {
                "id": resource_id,
                "open_ports": resource_open_ports,
                "enabled_ssl_version": enabled_ssl_version
            }
            self.aggregated_resource_list.append(aggregated_result)

        return self.aggregated_resource_list

    def read_file(self,file_name):
        f = open(file_name, "r")
        json_string = f.read()
        json_objects = json.loads(json_string)
        self.resource_file = json_objects

    def extract_id(self,index):   
        return self.resources[index]["id"]

    def extract_open_ports(self, index): 
        ports = self.resources[index]['ports']
        return list(ports.keys())

    def extract_enabled_ssl_version(self,open_ports, index):
        enabled_ssl_version = []

        for port in open_ports:
            dict_port: dict = self.resources[index]["ports"][port]
            if ("ssl_protocol" in dict_port.keys()):
                ssl_procotol: dict = dict_port["ssl_protocol"]
                if "enabled" in ssl_procotol.keys():
                    enabled_ssl_version.extend(ssl_procotol["enabled"])
            
        return enabled_ssl_version      

class RuleEngine:
    def __init__(self) -> None:
        self.resources = None
        self.rules = None
    
    def set_resources(self, resources):
        self.resources = resources
    
    def set_rules(self, rules):
        self.rules = rules

    def run_evaluator(self):
        issues = {}
        for resource in self.resources:
            applied_rules = self.get_applied_rule(resource)
            final_rules = {}
            local_rules = (self.rules["rules"]).copy()
            for rule in local_rules:
                if (rule['name'] in applied_rules or rule['name'] == "*"):
                    for key in rule.keys():
                        if key == 'name':
                            continue
                        if (key not in final_rules.keys()):
                            if (type(rule[key]) is list):
                                final_rules[key] = (rule[key]).copy()
                            else:
                                final_rules[key] = rule[key]
                        else:
                            if (type(rule[key]) is list and type(final_rules[key]) is list):
                                final_rules[key].extend(rule[key])
                            elif (type(rule[key]) is not list and type(final_rules[key]) is list):
                                final_rules[key].append(rule[key])
                            elif (type(rule[key]) is list and type(final_rules[key] is not list)):
                                new_list = (rule[key]).copy()
                                new_list.append(final_rules[key])
                                final_rules[key] = new_list
                            else:
                                final_rules[key] = [rule[key], final_rules[key]]
            
            issue = self.evalute_resource(resource, final_rules)
            if issue:
                issues[resource['id']] = issue
        for key in issues:
            print(key + "      ", end=" ")
            print(issues[key])

    def evalute_resource (self, resource, applied_rules):
        if not resource: return False

        issues_found = []
        open_ports = resource['open_ports']
        
        for open_port in open_ports:
            open_port = int(open_port)
            
            if (open_port not in applied_rules['open_ports']):
                issues_found.append("Port "+ str(open_port) + " should not be open")

        enabled_ssl_versions = resource['enabled_ssl_version']

        for ssl_version in enabled_ssl_versions:
            if (ssl_version not in applied_rules['enabled_ssl_version']):
                issues_found.append("SSL version " + ssl_version + " is deprecated")

        for port_pair in applied_rules['port_pairs']:
            if (port_pair[0] in open_ports and port_pair[1] in open_ports):
                issues_found.append("Two insecure port are open " + port_pair)
        return issues_found


    def get_applied_rule(self, resource:dict, rule=None):
        # filter(lambda rule: rule['id'] == resource['id'], self.resources['applied_rules'])
        
        if (rule == None and self.rules == None):
            print("Rules are requried")
            return
        enforced_rules = []
        for applied_rule in self.rules['applied_rules']:
            if applied_rule['id'] == resource['id']:
                enforced_rules.extend(applied_rule['enforced_rules'])

        return enforced_rules
        



def main():

    parser = argparse.ArgumentParser(description='Validates the resource against rules')
    parser.add_argument('--rules', help='rules file as a json', default='rules.json', dest='rules_file_name')
    parser.add_argument('--resource', help='resource file to be validated as a json', default='resource.json', dest='resource_file_name')
    
    args=(parser.parse_args())
    rules_file_name = args.rules_file_name
    resource_file_name = args.resource_file_name

    if (not os.path.exists(rules_file_name)):
        print("Please make sure "+ rules_file_name +" exists")
        return 
    if (not os.path.exists(resource_file_name)):
        print("Please make sure "+ resource_file_name + " exists")
        return
    
    rule_manager = RuleManager()
    rule_manager.set_rules_file(rules_file_name)
    is_rule_structure_valid = rule_manager.validate_rule_structure()

    if (not is_rule_structure_valid):
        print("Something is wrong with Rule structure")
        return
    # print(rule_engine.rules)

    resources_manager = ResourceManager()
    resources_manager.set_resource_files(resource_file_name)
    resources_dict_list = resources_manager.get_resource_properties()
    if (not resources_manager.is_valid_resource):
        print("Something is wrong resources files")
        return 

    rule_engine = RuleEngine()
    rule_engine.set_resources(resources_dict_list)
    rule_engine.set_rules(rule_manager.get_rules())

    rule_engine.run_evaluator()


main()