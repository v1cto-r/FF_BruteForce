FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    mininet \
    openvswitch-switch \
    net-tools \
    iputils-ping \
    tcpdump \
    python3 \
    python3-pip \
    python3-scapy \
    iproute2 \
    frr \
    frr-pythontools \
    vim \
    less \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /data/FF_BruteForce

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
