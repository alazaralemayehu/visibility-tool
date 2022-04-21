import os
import argparse
from Validator import *

def main():

    parser = argparse.ArgumentParser(description='Validates the resource against rules')
    parser.add_argument('--rules', help='rules file as a json', default='rules.json', dest='rules_file_name')
    parser.add_argument('--res', help='resource file to be validated as a json', default='resource.json', dest='resource_file_name')
    parser.add_argument('--res2', help='resource file to be compared with the recent json file as a json file', default=None, dest='resource_file_name2')
    
    args=(parser.parse_args())

    rules_file_name = args.rules_file_name
    resource_file_name = args.resource_file_name
    resource_file_name2 = args.resource_file_name2

    rule_manager = RuleManager()

    resources_manager = ResourceManager()


    if (resource_file_name2 is not None):
        if (not os.path.exists(resource_file_name2)):
            print("Please make sure " + resource_file_name2 +" file exists.")
            return
        resources_manager.set_resource_files(resource_file_name2)
       
    
    if (not os.path.exists(rules_file_name)):
        print("Please make sure "+ rules_file_name +" exists")
        return 
    if (not os.path.exists(resource_file_name)):
        print("Please make sure "+ resource_file_name + " exists")
        return
    
    
    rule_manager.set_rules_file(rules_file_name)
    is_rule_structure_valid = rule_manager.validate_rule_structure()

    if (not is_rule_structure_valid):
        print("Something is wrong with Rule structure")
        return

    updated_resources = None
    resources_manager.set_resource_files(resource_file_name)

    if (resource_file_name2 is not None):
        jsondiff = JsonDifference()
        jsondiff.set_jsons(Utilities.read_file(resource_file_name), Utilities.read_file(resource_file_name2))
        
        updated_resources = jsondiff.compute_difference()

    if updated_resources is None:
        resources_dict_list = resources_manager.get_resource_properties()
    else:
        resources_dict_list = updated_resources
         
    rule_engine = RuleEngine()
    rule_engine.set_resources(resources_dict_list)
    rule_engine.set_rules(rule_manager.get_rules())

    rule_engine.run_evaluator()


main()