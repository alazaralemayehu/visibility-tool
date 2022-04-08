ARG FUNCTION_DIR="/function"

FROM ubuntu:latest

ARG FUNCTION_DIR
RUN mkdir -p ${FUNCTION_DIR}
WORKDIR ${FUNCTION_DIR}
#Install aws-lambda-cpp build dependencies
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
    make static

RUN echo 'export PATH="$PATH:/function/sslscan"' >> /root/.bashrc
# Copy function code
COPY app/* ${FUNCTION_DIR}

# Install the runtime interface client
RUN pip3 install \
        python-nmap \
        deepdiff


# RUN echo "sbx_user1051:sbx_user1051" | chpasswd && adduser sbx_user1051 sudo
USER root

# ENTRYPOINT ["python3"]

CMD [ "python3", "main.py"]