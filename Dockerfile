FROM ubuntu:latest


ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go
ENV GOBIN=$GOPATH/bin
ENV PATH=$GOBIN:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1


RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl tar jq unzip sed python3 \
      libpcap-dev whois dnsutils openssl git ca-certificates \
      golang-go \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/frogy
COPY . /opt/frogy

RUN chmod +x *

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN cp $GOBIN/subfinder   /usr/local/bin/ \
 && cp $GOBIN/assetfinder /usr/local/bin/ \
 && cp $GOBIN/dnsx        /usr/local/bin/ \
 && cp $GOBIN/naabu       /usr/local/bin/ \
 && cp $GOBIN/httpx       /usr/local/bin/

RUN mkdir -p /opt/frogy/output

ENTRYPOINT ["bash", "frogy.sh"]
