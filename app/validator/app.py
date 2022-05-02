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
        recently_scan_json = json.loads(objects[0].get()['Body'].read().decode('utf-8'))
        penultimate_scan_json = json.loads(objects[1].get()['Body'].read().decode('utf-8'))
        return recently_scan_json,penultimate_scan_json    

def format_output_to_codedx(issues):
    formatted_issues = []
    for issue in issues:
        key = list((issue.keys()))[0]
        for instance_issue in issue[key]:
            new_format = {}
            new_format['id'] = key
            new_format['title'] = instance_issue
            new_format['description'] = 'Description'
            new_format['aws_account_id'] = 'aws_account_id'
            new_format['tool'] = 'SSLScan' if 'SSL' in instance_issue else 'Nmap'

            formatted_issues.append(new_format)
    return formatted_issues
def main(event, context):

    rule_manager = RuleManager()
    resources_manager = ResourceManager()
    rule_engine = RuleEngine()
    
    get_only_current_state_the_resource = True
    updated_resources = None

    rules_file_name = 'rules.json'
    rule_manager.set_rules_file(rules_file_name)

    if (not rule_manager.validate_rule_structure()):
        print("Something is wrong with Rule structure")
        return

    recently_scan_json , penultimate_json = run_aws_lambda()

    if (recently_scan_json is None and penultimate_json is None):
            print("Please make sure the bucket is not empty or you have access to those files.")
            return

    resources_manager.set_resource(recently_scan_json)

    if not get_only_current_state_the_resource:
        if (penultimate_json is not None and recently_scan_json is not None):
            json_diff = JsonDifference()
            json_diff.set_jsons(penultimate_json, recently_scan_json)
            
            updated_resources = json_diff.compute_difference()

    if updated_resources is None:
        resources_dict_list = resources_manager.get_resource_properties()
    else:
        resources_dict_list = updated_resources
         
    rule_engine.set_resources(resources_dict_list)
    rule_engine.set_rules(rule_manager.get_rules())
    result = rule_engine.run_evaluator()
    formatted_output_to_codedx = format_output_to_codedx(result)
    return formatted_output_to_codedx