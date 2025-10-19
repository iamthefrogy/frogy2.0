FROM golang:1.24-bookworm AS builder

ENV GOBIN=/out
RUN mkdir -p "$GOBIN"

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      git ca-certificates build-essential pkg-config libpcap-dev \
  && rm -rf /var/lib/apt/lists/*

ARG SUBFINDER_VER=latest
ARG ASSETFINDER_VER=latest
ARG DNSX_VER=latest
ARG NAABU_VER=latest
ARG HTTPX_VER=latest
ARG GAU_VER=latest
ARG KATANA_VER=latest
ARG TLSX_VER=latest

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VER} \
 && go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VER} \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VER} \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VER} \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VER} \
 && go install github.com/lc/gau/v2/cmd/gau@${GAU_VER} \
 && go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VER} \
 && go install github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VER}

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      ca-certificates curl zip unzip jq sed python3 python3-pip python3-venv whois dnsutils openssl \
      bash libpcap0.8 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/frogy

COPY requirements.txt ./requirements.txt
RUN python3 -m venv /opt/frogy/.venv \
 && /opt/frogy/.venv/bin/pip install --upgrade pip \
 && /opt/frogy/.venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .

RUN sed -i 's/\r$//' frogy.sh || true \
 && chmod 0755 frogy.sh entrypoint.sh

COPY --from=builder /out/* /usr/local/bin/
ENV PATH=/opt/frogy/.venv/bin:/usr/local/bin:$PATH

RUN mkdir -p /opt/frogy/output

ENV FROGY_WEB_PORT=8787
EXPOSE 8787

ENTRYPOINT ["./entrypoint.sh"]
