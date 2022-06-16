
# visibility-tool

This project is an artefact for Master's thesis entitled "Continuous monitoring approach for visibility into the security footprint of an IoT cloud platform".

The project has Two main components; Scanner and Validator; The scanner is dockerized into a package. please check for the requirement folders in the project (Check gitignore to see what is left from being committed)
The the project is divided into two parts, the first one is Scanner while the second one is validator.

The scanner is found in main branch while the validator is found in validator-aws-s3 branch.

## Installation
This project deployed locally or using docker. To run the project locally the following python modules are required: - python-nmap - deepdiff - boto3 - dnspython. Additionally sslscan and nmap should be install on local machine.

To deploy it using Docker,
- first clone the following code. 
- Go to main.py file `response = upload_file(file_name, 'vulnscan-bucket')` and change the vulscan-bucket with your own bucket name.
- If you are not using EC2 instance, create .aws folder and put AWS credential inside it and go to Dockerfile and uncomment `RUN mkdir -p /root/.aws COPY .aws /root/.aws lines`
-  .aws folder which contains config and credentials files - the config file should contiain region = eu-north-1 output = json - the credential file should contain: [default] aws_access_key_id = aws access key id aws_secret_access_key = aws secret access key
- The above few steps setup the deployment environment and also create a file named links.txt inside the app folder. The file should contain list of files that you need to scan.
- `Run docker build -t image_name .` - build the docker image
- `docker run --rm image-name --net=host.` - run the docker container

## Running validator
- checkout to validator-aws-s3
- use the following link to deploy to the aws lambda
https://docs.aws.amazon.com/lambda/latest/dg/images-create.html
