#!/usr/bin/env bash
# Exit immediately if any command fails, unset variables are errors, and fail on pipe errors.
set -euo pipefail

##############################################
# Logging Functions
##############################################
info() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [+] $*"
}
warning() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [!] $*"
}
error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [-] $*" >&2
}

##############################################
# Sudo Check
##############################################
if ! sudo -n true 2>/dev/null; then
  info "This script requires sudo privileges. Please ensure your user is in the sudoers list."
  sudo -v
fi

##############################################
# OS Detection
##############################################
OS_TYPE=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian|kali)
      OS_TYPE="debian"
      ;;
    fedora|rhel|centos)
      OS_TYPE="rhel"
      ;;
    arch)
      OS_TYPE="arch"
      ;;
    *)
      error "Unsupported OS: $ID"
      exit 1
      ;;
  esac
else
  error "Cannot detect OS type. Exiting."
  exit 1
fi
info "Detected OS type: $OS_TYPE"

##############################################
# Dependency Installation Functions
##############################################
install_dependencies_debian() {
  info "Installing dependencies for Debian-based systems..."
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    jq curl unzip sed python3 libpcap-dev whois dnsutils openssl golang-go
}

install_dependencies_rhel() {
  info "Installing dependencies for RedHat-based systems..."
  if command -v dnf > /dev/null 2>&1; then
    sudo dnf install -y epel-release
    sudo dnf install -y jq curl unzip sed python3 libpcap-devel whois bind-utils openssl golang
  else
    sudo yum install -y epel-release
    sudo yum install -y jq curl unzip sed python3 libpcap-devel whois bind-utils openssl golang
  fi
}

install_dependencies_arch() {
  info "Installing dependencies for Arch-based systems..."
  sudo pacman -S --needed --noconfirm jq curl unzip sed python libpcap whois bind dnsutils openssl golang
}

case "$OS_TYPE" in
  debian)
    install_dependencies_debian
    ;;
  rhel)
    install_dependencies_rhel
    ;;
  arch)
    install_dependencies_arch
    ;;
  *)
    error "Unsupported OS type: $OS_TYPE"
    exit 1
    ;;
esac

##############################################
# Verify Go Installation
##############################################
if ! command -v go &>/dev/null; then
  error "Go is not installed. Please install Go manually."
  exit 1
fi

# Determine GOPATH and GOBIN (default GOPATH is $HOME/go if not set)
GOPATH=$(go env GOPATH)
GOBIN="${GOPATH}/bin"
info "Using GOPATH: ${GOPATH}"

##############################################
# Go Tools Installation Functions
##############################################
install_go_tool() {
  local tool_url="$1"
  local tool_name="$2"
  info "Installing ${tool_name}..."
  go install "${tool_url}"@latest
  if [ ! -f "${GOBIN}/${tool_name}" ]; then
    warning "${tool_name} binary not found in ${GOBIN}. It may not have installed correctly."
  fi
}

install_go_tools() {
  install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
  install_go_tool "github.com/tomnomnom/assetfinder" "assetfinder"
  install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx" "dnsx"
  install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu" "naabu"
  install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
}

install_go_tools

##############################################
# Copying Binaries to /usr/local/bin
##############################################
copy_binaries() {
  info "Copying installed Go binaries to /usr/local/bin..."
  local tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx")
  for tool in "${tools[@]}"; do
    if [ -f "${GOBIN}/${tool}" ]; then
      sudo cp "${GOBIN}/${tool}" /usr/local/bin/ && info "Copied ${tool} to /usr/local/bin"
    else
      warning "${tool} not found in ${GOBIN}"
    fi
  done
}

copy_binaries

##############################################
# Verify Installed Binaries in PATH
##############################################
check_binaries() {
  info "Verifying that all installed tools are available in your PATH..."
  local tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx")
  local missing=()
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      missing+=("$tool")
    else
      info "$tool found at $(command -v "$tool")"
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    error "The following tools are missing from PATH: ${missing[*]}"
    error "Ensure that ${GOBIN} is in your PATH or that the binaries have been copied to /usr/local/bin."
    exit 1
  else
    info "All required tools are installed and available in PATH."
  fi
}

check_binaries

info "Installation complete. If you encounter issues, please verify that /usr/local/bin is in your PATH."
