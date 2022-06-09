import datetime
import io
import json
import logging
import requests
from deepdiff import DeepDiff
import xml.etree.ElementTree as ET
import boto3
import boto3.session
import subprocess
from Validator import *


def run_aws_lambda():
    f = open("config.txt", "r")
    
    # content of config.txt file should look like
    # aws_acess_key_id
    # aws_secret_access_key
    
    lines = f.readlines()
    aws_access_key_id = lines[0].strip()
    aws_secret_acces_key = lines[1].strip()
    print(subprocess.check_output([ "whoami"]))

    # conn = boto3.client()
    conn = boto3.session.Session(
    #     aws_access_key_id= aws_access_key_id,
    #     aws_secret_access_key= aws_secret_acces_key
    )

    s3 = conn.resource("s3")
    # for bucket in s3.buckets.all()
    bucket = s3.Bucket("scanner_bucket")
    objects =list(bucket.objects.all())
    if (len(objects)== 0):
        return None, None
    elif (len(objects) == 1):
        return json.loads(objects[0].get()["Body"].read().decode("utf-8")), None
    else:
        objects.sort(key=lambda object: object.last_modified, reverse=True)
        recently_scan_json = json.loads(objects[0].get()["Body"].read().decode("utf-8"))
        penultimate_scan_json = json.loads(objects[1].get()["Body"].read().decode("utf-8"))
        return recently_scan_json,penultimate_scan_json    

def format_output_to_codedx(issues):
    formatted_issues = []
    
    print("before format ")
    print(issues)
    for issue in issues:
        key = list((issue.keys()))[0]
        current_issue = {key:[]}

        for instance_issue in issue[key]:
            new_format = {}
            new_format["id"] = key
            new_format["title"] = instance_issue
            new_format["description"] = "Description"
            new_format["aws_account_id"] = "aws_account_id"
            new_format["tool"] = "SSLScan" if "SSL" in instance_issue else "Nmap"
            new_format["severity"] = "medium"
            current_issue[key].append(new_format)
        formatted_issues.append(current_issue)
    print("Formatted secret")
    print(formatted_issues)
    secret = get_secret()
    
    return formatted_issues

def get_secret():

        
    secret_name = ""
    region_name = "eu-west-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the "GetSecretValue" API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

                 
    region_name = "eu-west-1"
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name
    )
    get_secret_value_response = client.get_secret_value(SecretId = secret_name)
    secret = json.loads(get_secret_value_response["SecretString"])["codedx"]
    return secret
    
    # invoke_response = lambda_client.invoke(FunctionName="vulscanner-validator-lambda", InvocationType="Event", Payload=json.dumps(msg))
    # print(invoke_response)



def sendFileForAnalysis(project_id, report_xml):
    codedx_url = "" 
    print("sending")
    report_xml.seek(0,0)
    # Can't use getHeader as Content-Type can't be *
    secret = get_secret()
    print("secret " + secret)

    response = requests.post(codedx_url + "/api/projects/" + str(project_id) + "/analysis", headers={'API-Key': secret, 'Accept': '*/*'}, files={"file": report_xml.getvalue()})
    print(response.status_code)
    print(str(response.content))
    if response.status_code == 200 or response.status_code == 202:
        print("File has been sent!")
        return response.json()['jobId']

def addToVulscannerXML(findings, row):
    finding = ET.SubElement(findings, "finding", {"id": row["id"],"type": "vulscanner", "severity": row["severity"], "description": row["description"], "tool": row["tool"], "aws_account_id":row["aws_account_id"]})
    ET.SubElement(finding, 'tool', {'name': 'vulscanner',
                                    'category': 'Security',
                                    'code': row["title"]
                                    })       
def send_result_to_codedx(issues):

    for issue in issues:
        report_xml = ET.Element("report", {"date": datetime.datetime.now().isoformat(),"tool": "vulscanner"})
        findings = ET.Element("findings")
        key = list((issue.keys()))[0]
        for finding in issue[key]:
            addToVulscannerXML(findings, finding)
        report_xml.append(findings)
        tree = ET.ElementTree(report_xml)
        cvms_xml = io.BytesIO()
        tree.write(cvms_xml, xml_declaration=True, encoding="utf-8", method="xml")
        sendFileForAnalysis(getProjectIdByName(key), cvms_xml) 

        print("sent")
def getHeader(apikey):
    return {
            'API-Key': apikey,
            'Accept': '*/*',
            'Content-Type': '*/*'
        }
def getProjectIdByName(repository):
    codedx_url = "" 

    codedx_filter = "{\"filter\": { \"name\": \"" + repository + "\"}}"
    response = requests.post(codedx_url + "/api/projects/query", headers=getHeader(get_secret()), data=codedx_filter)
    if response.status_code == 200:
        for project in response.json():
            if project['name'] == repository:
                if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                    logging.debug(project)
                return project['id']
        # If project list is is empty or not contain exact the same project name than given as repository
        logging.error("Project: " + repository + " not found!")
    else:
        logging.error("getProjectIdByName returned")
        logging.error(response)

def main(event, context):

    rule_manager = RuleManager()
    resources_manager = ResourceManager()
    rule_engine = RuleEngine()
    
    get_only_current_state_the_resource = True
    updated_resources = None

    rules_file_name = "rules.json"
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
    send_result_to_codedx(formatted_output_to_codedx)
    return formatted_output_to_codedx

