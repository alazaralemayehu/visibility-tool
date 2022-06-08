FROM public.ecr.aws/lambda/python:3.8

RUN pip3 install \
        python-nmap \
        deepdiff \
        requests \
        boto3 \
        dnspython --target "${LAMBDA_TASK_ROOT}"
COPY . ${LAMBDA_TASK_ROOT}

CMD [ "app.main" ]

 