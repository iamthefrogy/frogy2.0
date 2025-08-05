# Use the most recent Ubuntu LTS as the base image.
FROM ubuntu:latest

## -----------------------------------------------------------------------------
##  Environment configuration
##
## Suppress interactive prompts, define Go paths, and extend PATH so Go tools are
## discoverable system-wide.
## -----------------------------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go
ENV GOBIN=$GOPATH/bin
ENV PATH=$GOBIN:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1

## -----------------------------------------------------------------------------
##  Install system dependencies & Go compiler
##
## Includes build-essential/pkg-config for cgo (pcap), libpcap-dev, network tools,
## json parser, unzip, sed, Python3, whois, openssl, git.
## -----------------------------------------------------------------------------
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl tar jq unzip sed python3 \
      libpcap-dev whois dnsutils openssl git ca-certificates \
      golang-go \
 && rm -rf /var/lib/apt/lists/*

## -----------------------------------------------------------------------------
##  Copy project files
##
## Bring your Frogy scripts and HTML templates into the image.
## -----------------------------------------------------------------------------
WORKDIR /opt/frogy
COPY . /opt/frogy

# Make scripts executable (for your reference; not run at build time)
RUN chmod +x *

## -----------------------------------------------------------------------------
##  Build & install Go-based tools
##
## Compile subfinder, assetfinder, dnsx, naabu, httpx into $GOBIN, then copy to
## /usr/local/bin for system-wide availability.
## -----------------------------------------------------------------------------
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

## -----------------------------------------------------------------------------
##  Prepare default output directory
##
## So Frogy can write results without creating dirs at runtime. Users can mount
## volumes over /opt/frogy/output to persist results.
## -----------------------------------------------------------------------------
RUN mkdir -p /opt/frogy/output

## -----------------------------------------------------------------------------
##  Entrypoint & default cmd
##
## ENTRYPOINT forwards any args to frogy.sh. If no domains file is specified,
## frogy.sh will print usage.
## -----------------------------------------------------------------------------
ENTRYPOINT ["bash", "frogy.sh"]
CMD ["primary_domains.txt"]
