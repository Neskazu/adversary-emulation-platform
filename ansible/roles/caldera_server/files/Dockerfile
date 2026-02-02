FROM mitre/caldera:latest

USER root

RUN apt-get update && \
    apt-get install -y wget ca-certificates && \
    wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
    rm go1.21.6.linux-amd64.tar.gz && \
    ln -sf /usr/local/go/bin/go /usr/bin/go

ENV PATH="/usr/local/go/bin:${PATH}"