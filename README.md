# E502 OSINT Terminal

A powerful, modular OSINT terminal built from scratch in Python. This tool provides comprehensive reconnaissance capabilities for security researchers and penetration testers.

## Features

### Network Analysis
- Network topology mapping
- ARP scanning for local network discovery
- MAC address vendor lookup
- Network device fingerprinting
- Service enumeration
- Port scanning

### Web Reconnaissance
- Web technology stack detection
- Content Security Policy (CSP) analysis
- Web Application Firewall (WAF) detection
- JavaScript library and framework detection
- Cookie security analysis
- Security header analysis

### SSL/TLS Analysis
- Cipher suite analysis
- Certificate transparency log checking
- SSL/TLS version support
- HSTS policy analysis
- Certificate chain validation
- Security recommendations

### Privacy Features
- Multiple proxy support (not just Tor)
- Proxy chain configuration
- User agent rotation
- Request rate limiting
- IP rotation capabilities
- Request history tracking

### Vulnerability Assessment
- Common vulnerability scanning
- Security header analysis
- Open port service enumeration
- Default credential checking
- Web vulnerability detection
- Service misconfiguration detection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Z3r0s/E502Scanner.git
cd E502OSINT
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tool:
```bash
python E502OSINT.py
```

## Usage

The E502 OSINT Terminal provides an interactive command-line interface. Here are some example commands:

### Network Analysis
```bash
network <target>     # Perform network topology mapping
arp <interface>      # Perform ARP scan on interface
fingerprint <target> # Perform device fingerprinting
```

### Web Analysis
```bash
web <url>           # Analyze website technology stack
headers <url>       # Check security headers
waf <url>          # Detect web application firewall
cookies <url>       # Analyze cookie security
```

### SSL/TLS Analysis
```bash
ssl <hostname>      # Analyze SSL/TLS configuration
cert <hostname>     # Check SSL certificate
ciphers <hostname>  # Analyze cipher suites
hsts <hostname>     # Check HSTS configuration
```

### Vulnerability Assessment
```bash
vuln <target>       # Perform vulnerability scan
ports <target>      # Scan for open ports
services <target>   # Enumerate services
creds <target>      # Check default credentials
```

### Privacy Features
```bash
proxy add <name> <host> <port> <type> # Add new proxy
proxy chain <proxy1> <proxy2> ...     # Create proxy chain
proxy status                           # Show proxy status
rate <domain> <requests/sec>          # Set rate limit
rotate                                # Rotate user agent
```

## Security Notice

This tool is designed for authorized security testing and research purposes only. Always:
- Obtain proper authorization before testing any system
- Follow responsible disclosure practices
- Respect privacy and data protection laws
- Use the tool ethically and responsibly

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

- z3r0s / Error502

## Acknowledgments

- Thanks to all the open-source projects that made this tool possible
- Special thanks to the security community for their continuous support 
