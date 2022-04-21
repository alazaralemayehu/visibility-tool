import json
from deepdiff import DeepDiff
import boto3
import boto3.session
from Validator import *
def run_aws_lambda():
    f = open('config.txt', 'r')
    
    # content of config.txt file should look like
    # aws_acess_key_id
    # aws_secret_access_key
    
    lines = f.readlines()
    aws_access_key_id = lines[0].strip()
    aws_secret_acces_key = lines[1].strip()


    conn = boto3.session.Session(
        aws_access_key_id= aws_access_key_id,
        aws_secret_access_key= aws_secret_acces_key
    )

    s3 = conn.resource('s3')
    # for bucket in s3.buckets.all()
    bucket = s3.Bucket('test-vulscanner')
    objects =list(bucket.objects.all())
    if (len(objects)== 0):
        return None, None
    elif (len(objects) == 1):
        return json.loads(objects[0].get()['Body'].read().decode('utf-8')), None
    else:
        objects.sort(key=lambda object: object.last_modified, reverse=True)
        first_object_content = json.loads(objects[0].get()['Body'].read().decode('utf-8'))
        second_object_content = json.loads(objects[1].get()['Body'].read().decode('utf-8'))
        return first_object_content,second_object_content    
        
def main():

    rule_manager = RuleManager()
    resources_manager = ResourceManager()

    rules_file_name = 'rules.json'
    rule_manager.set_rules_file(rules_file_name)

    is_rule_structure_valid = rule_manager.validate_rule_structure()

    if (not is_rule_structure_valid):
        print("Something is wrong with Rule structure")
        return

    resource_content , resource_content_2 = run_aws_lambda()
    

    if (resource_content is None and resource_content_2 is None):
            print("Please make sure the bucket is not empty or you have access to those files.")
            return

    updated_resources = None
    resources_manager.set_resource(resource_content)

    if (resource_content_2 is not None and resource_content is not None):
        jsondiff = JsonDifference()
        jsondiff.set_jsons(resource_content, resource_content_2)
        
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