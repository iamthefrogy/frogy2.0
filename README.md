# Frogy 2.0

**Frogy 2.0** is an automated external reconnaissance and Attack Surface Management (ASM) toolkit designed to map out an organization's entire internet presence. It identifies assets, IP addresses, web applications, and other metadata across the public internet and then smartly prioritizes them from P0 (most attractive) to P4 (least attractive) from a bug bounty hunter's perspective.

## Features

- **Comprehensive Recon:**  
  Aggregate subdomains and assets using multiple tools (CHAOS, Subfinder, Assetfinder, crt.sh) to map an organization's entire digital footprint.
  
- **Live Asset Verification:**  
  Validate assets with live DNS resolution and port scanning (using DNSX and Naabu) to confirm what is publicly reachable.
  
- **In-depth Web Recon:**  
  Collect detailed HTTP response data (via HTTPX) including metadata, technology stack, status codes, content lengths, and more.
  
- **Smart Prioritization:**  
  Use a composite scoring system that considers homepage status, content length, technology stack, and DNS data to categorize assets from P0 to P4—helping bug bounty hunters and pentesters focus on the most promising targets.
  
- **Professional Reporting:**  
  Generate a dynamic, color-coded HTML report with a modern design and dark/light theme toggle.

## Installation

Clone the repository and run the installer script to set up all dependencies and tools:

```bash
chmod +x install.sh
./install.sh
```
## Usage

Clone the repository and run the installer script to set up all dependencies and tools:

```bash
chmod +x frogy.sh
./frogy.sh
