import json
from deepdiff import DeepDiff
import boto3
import boto3.session
import subprocess
from Validator import *
def run_aws_lambda():
    f = open('config.txt', 'r')
    
    # content of config.txt file should look like
    # aws_acess_key_id
    # aws_secret_access_key
    
    lines = f.readlines()
    aws_access_key_id = lines[0].strip()
    aws_secret_acces_key = lines[1].strip()
    print(subprocess.check_output([ "whoami"]))

    # conn = boto3.client()
    # conn = boto3.session.Session(
    #     aws_access_key_id= aws_access_key_id,
    #     aws_secret_access_key= aws_secret_acces_key
    # )

    s3 = boto3.resource('s3')
    # for bucket in s3.buckets.all()
    bucket = s3.Bucket('vulnscanner-result')
    objects =list(bucket.objects.all())
    print("length of the S3 is")
    print(len(objects))
    if (len(objects)== 0):
        return None, None
    elif (len(objects) == 1):
        return json.loads(objects[0].get()['Body'].read().decode('utf-8')), None
    else:
        objects.sort(key=lambda object: object.last_modified, reverse=True)
        print(objects)
        recently_uploaded_object = json.loads(objects[0].get()['Body'].read().decode('utf-8'))
        previously_uploaded_object = json.loads(objects[1].get()['Body'].read().decode('utf-8'))
        return recently_uploaded_object,previously_uploaded_object    
        
def main(event, context):

    rule_manager = RuleManager()
    resources_manager = ResourceManager()

    rules_file_name = 'rules.json'
    rule_manager.set_rules_file(rules_file_name)

    is_rule_structure_valid = rule_manager.validate_rule_structure()

    if (not is_rule_structure_valid):
        print("Something is wrong with Rule structure")
        return

    recently_uploaded_object , previously_uploaded_object = run_aws_lambda()

    if (recently_uploaded_object is None and previously_uploaded_object is None):
            print("Please make sure the bucket is not empty or you have access to those files.")
            return

    updated_resources = None
    resources_manager.set_resource(recently_uploaded_object)

    if (previously_uploaded_object is not None and recently_uploaded_object is not None):
        jsondiff = JsonDifference()
        jsondiff.set_jsons(previously_uploaded_object, recently_uploaded_object)
        
        updated_resources = jsondiff.compute_difference()
        print(updated_resources)

    if updated_resources is None:
        resources_dict_list = resources_manager.get_resource_properties()
    else:
        resources_dict_list = updated_resources
         
    rule_engine = RuleEngine()
    rule_engine.set_resources(resources_dict_list)
    rule_engine.set_rules(rule_manager.get_rules())

    rule_engine.run_evaluator()

