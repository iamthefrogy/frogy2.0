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
      bash libpcap0.8 fonts-liberation xdg-utils \
      libasound2t64 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libcairo2 libcups2 libdbus-1-3 \
      libdrm2 libgbm1 libgdk-pixbuf-2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 \
      libpango-1.0-0 libpangocairo-1.0-0 libu2f-udev libx11-6 libx11-xcb1 libxcb1 libxcomposite1 \
      libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxkbcommon0 libxrandr2 libxrender1 libxss1 libxtst6 \
      libxshmfence1 \
  && rm -rf /var/lib/apt/lists/*

# Install a system Chromium browser when available (amd64); otherwise rely on httpx's bundled engine
RUN arch="$(dpkg --print-architecture)" \
 && if [ "$arch" = "amd64" ]; then \
      apt-get update -qq \
      && apt-get install -y --no-install-recommends gnupg wget apt-transport-https \
      && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-linux.gpg \
      && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
      && apt-get update -qq \
      && apt-get install -y --no-install-recommends google-chrome-stable \
      && apt-get purge -y --auto-remove gnupg wget apt-transport-https \
      && rm -rf /var/lib/apt/lists/*; \
    else \
      echo "Skipping system Chrome install for architecture ${arch}; httpx will download a bundled browser."; \
    fi

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
ENV XDG_CACHE_HOME=/opt/frogy/.cache

RUN mkdir -p /opt/frogy/output /opt/frogy/.cache

ENV FROGY_WEB_PORT=8787
EXPOSE 8787

ENTRYPOINT ["./entrypoint.sh"]
