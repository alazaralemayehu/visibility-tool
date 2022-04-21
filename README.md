# visibility-tool
This project is an artefact for Master's thesis entitled "Continuous monitoring approach for visibility into the security footprint of an IoT cloud platform".

The project has Two main components; Scanner and Validator;
The scanner is dockerized into a package. 
please check for the requirement folders in the project (Check gitignore to see what is left from being committed)

# Installation 

This project deployed locally or using docker. To run the project locally the following python modules are required:
        - python-nmap
        - deepdiff
        - boto3
        - dnspython

Additionally, the project assumes that **nmap** and **sslscan version 2** is installed on local machine.

The second way to deploy this project is using docker. For the docker deployment to work, The following folders and files are required (This files are not checked in the git file for security reason):
    - .aws folder which contains config and credentials files
    - the config file should contiain
            region = eu-north-1
            output = json
    - the credential file should contain:
        [default]
        aws_access_key_id = aws access key id
        aws_secret_access_key = aws secret access key