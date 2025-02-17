#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# OS Detection and Package Installation
# ---------------------------
echo "Detecting OS..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  echo "Cannot detect OS type. Exiting."
  exit 1
fi
echo "Detected OS: $OS"

install_dependencies() {
  echo "Installing common dependencies for Debian/Ubuntu/Kali..."
  sudo apt-get update
  sudo apt-get install -y jq curl unzip sed python3 libpcap-dev
}

install_dependencies_redhat() {
  echo "Installing common dependencies for RedHat-based systems..."
  if command -v dnf > /dev/null 2>&1; then
    sudo dnf install -y epel-release
    sudo dnf install -y jq curl unzip sed python3 libpcap-devel
  else
    sudo yum install -y epel-release
    sudo yum install -y jq curl unzip sed python3 libpcap-devel
  fi
}

case "$OS" in
  ubuntu|debian|kali)
    echo "Using apt-get for installation..."
    install_dependencies
    ;;
  rhel|centos|fedora|redhat)
    echo "Using yum/dnf for installation..."
    install_dependencies_redhat
    ;;
  *)
    echo "Unsupported OS: $OS. Exiting."
    exit 1
    ;;
esac

# ---------------------------
# Check for Go and install if missing
# ---------------------------
if ! command -v go &> /dev/null; then
  echo "Go is not installed. Installing Go..."
  case "$OS" in
    ubuntu|debian|kali)
      sudo apt-get install -y golang-go
      ;;
    rhel|centos|fedora|redhat)
      if command -v dnf &> /dev/null; then
        sudo dnf install -y golang
      else
        sudo yum install -y golang
      fi
      ;;
    *)
      echo "Unsupported OS for automatic Go installation. Please install Go manually."
      exit 1
      ;;
  esac
else
  echo "Go is already installed."
fi

# ---------------------------
# Install Go-Based Tools
# ---------------------------
echo "Installing Go-based tools (ensure your GOPATH/bin is in your PATH)..."

echo "Installing subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest

echo "Installing dnsx..."
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "Installing naabu..."
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ---------------------------
# Copy binaries to /usr/local/bin if not already in PATH
# ---------------------------
copy_binaries() {
  echo "Copying installed binaries to /usr/local/bin..."
  GOBIN=$(go env GOPATH)/bin
  local tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx")
  for tool in "${tools[@]}"; do
    if [ -f "$GOBIN/$tool" ]; then
      sudo cp "$GOBIN/$tool" /usr/local/bin/
      echo "$tool copied to /usr/local/bin"
    else
      echo "Warning: $tool not found in $GOBIN"
    fi
  done
}

copy_binaries

# ---------------------------
# Verify binaries are available in PATH
# ---------------------------
check_binaries() {
  echo "Verifying that all tools are installed and available in PATH..."
  local binaries=("subfinder" "assetfinder" "dnsx" "naabu" "httpx")
  local missing=0
  for bin in "${binaries[@]}"; do
    if ! command -v "$bin" &> /dev/null; then
      echo "Error: $bin not found in PATH."
      missing=1
    else
      echo "$bin found at $(command -v $bin)"
    fi
  done

  if [ $missing -ne 0 ]; then
    echo "One or more binaries are missing from your PATH."
    echo "Please ensure that your Go bin directory (typically $(go env GOPATH)/bin) is in your PATH, or the binaries have been copied to /usr/local/bin."
    exit 1
  else
    echo "All binaries are present."
  fi
}

check_binaries

echo "Installation complete."
echo "If you still have issues, verify that /usr/local/bin is in your PATH."
