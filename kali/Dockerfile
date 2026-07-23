FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       iproute2 \
       iputils-ping \
       nmap \
       tcpdump \
       tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /evidence
