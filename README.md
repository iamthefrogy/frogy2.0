# Frogy 2.0

**Frogy 2.0** is an automated external reconnaissance and Attack Surface Management (ASM) toolkit designed to map out an organization's entire internet presence. It identifies assets, IP addresses, web applications, and other metadata across the public internet and then smartly prioritizes them from P0 (most attractive) to P4 (least attractive) from a bug bounty hunter's perspective.

<img src="https://chintangurjar.com/images/frogyasm.png" alt="graphviz" width="700" height="600"/>

## Features

- **Comprehensive recon:**  
  Aggregate subdomains and assets using multiple tools (CHAOS, Subfinder, Assetfinder, crt.sh) to map an organization's entire digital footprint.
  
- **Live asset verification:**  
  Validate assets with live DNS resolution and port scanning (using DNSX and Naabu) to confirm what is publicly reachable.
  
- **In-depth web recon:**  
  Collect detailed HTTP response data (via HTTPX) including metadata, technology stack, status codes, content lengths, and more.
  
- **Smart prioritization:**  
  Use a composite scoring system that considers homepage status, content length, technology stack, and DNS data to categorize assets from P0 to P4—helping bug bounty hunters and pentesters focus on the most promising targets.
  
- **Professional reporting:**  
  Generate a dynamic, colour-coded HTML report with a modern design and dark/light theme toggle.

## Future Roadmap

- Enhance prioritisation for target picking.
- ~~Adding security and compliance-related data (SSL/TLS hygiene, SPF, Dmarc, Headers etc)~~
- Identifying customer-intended vs colleague-intended applications.
- Identified abandoned and unwanted applications.
- Identify traditional endpoints vs. API endpoints.
- Change font color in darkmode.
- ~~Allow to filter column data.~~
- ~~Add more analytics based on new data.~~
- ~~Idenfify login portals.~~
- ~~Basic dashboard/analytics if possible.~~
- ~~Identifying horizontal and vertical both domains.~~

## Installation

Clone the repository and run the installer script to set up all dependencies and tools:

```bash
chmod +x install.sh
./install.sh
```
## Usage

OPTION 1 - If you wish to use it against a specific organisation, then utilise frogy.sh. Here, you will enter the organisation's name, which will be searched in the CHAOS database and also fetch assets from there.
```bash
chmod +x frogy.sh
./frogy.sh
```

OPTION 2 - If you do not care about the names of organisations but wish to run it against the list of primary domains in the file, then use this. You can provide any file as the input file.
```bash
chmod +x frogy-multiple-domains.sh
./frogy-multiple-domains.sh domains.txt
```

Video Demo - https://www.youtube.com/watch?v=LHlU4CYNj1M
