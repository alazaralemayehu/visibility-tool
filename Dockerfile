ARG FUNCTION_DIR="/function"

FROM ubuntu:latest

# Define function directory
ARG FUNCTION_DIR
RUN mkdir -p ${FUNCTION_DIR}
WORKDIR ${FUNCTION_DIR}

#Install nmap, sslscan and build dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    g++ \
    make \
    cmake \
    unzip \
    libcurl4-openssl-dev\
    software-properties-common\
    iputils-ping \
    nmap && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.8 python3-distutils python3-pip python3-apt sudo && \
    apt-get install -y build-essential git zlib1g-dev && \
    sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list && \
    apt-get update -y && \
    apt-get build-dep openssl -y && \
    git clone https://github.com/rbsec/sslscan.git && \
    cd sslscan && \
    make static && \
    mv /function/sslscan/sslscan /bin/ &&\
# Setup aws client
    apt-get install curl; curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" &&\
    unzip awscliv2.zip && rm awscliv2.zip && \
    sudo ./aws/install
# install python dependencies
RUN pip3 install \
        python-nmap \
        deepdiff \
        boto3 \
        dnspython
# setup aws authentication configuration 
RUN mkdir -p /root/.aws
COPY .aws /root/.aws


COPY app/* ${FUNCTION_DIR}

CMD [ "python3", "main.py"]