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

### Image Intelligence
- EXIF data extraction and analysis
- Geolocation data extraction
- Hidden content detection (steganography)
- Visual anomaly analysis
- Image hashing and similarity detection
- Basic image information extraction
- Metadata steganography detection
- Image pattern analysis

### Username/Email Intelligence
- Username availability checking
- Email pattern analysis
- Username pattern generation
- Email format validation
- Username relationship mapping
- Email infrastructure analysis
- Username history tracking
- Email security analysis
- Pattern recognition
- Cross-platform correlation

### Discord Integration
- Real-time scan result notifications
- Rich embed formatting for results
- Customizable webhook configuration
- Scan history tracking
- Alert system with severity levels
- Automated reporting
- Scan summaries
- Activity monitoring

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Z3r0s/E502Scanner.git
cd E502Scanner
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

### Image Intelligence
```bash
image <path>        # Analyze image metadata and content
exif <path>         # Extract EXIF data
geo <path>          # Extract geolocation data
stego <path>        # Check for hidden content
hash <path>         # Generate image hashes
```

### Username/Email Intelligence
```bash
username <name>     # Check username availability
email <address>     # Analyze email patterns
pattern <name>      # Generate username patterns
history <name>      # Track username history
correlate <name>    # Map username relationships
```

### Discord Integration
```bash
discord help        # Show Discord commands
discord enable      # Enable Discord integration
discord disable     # Disable Discord integration
discord set <url>   # Set webhook URL
discord save        # Save webhook configuration
discord test        # Send test message
discord status      # Show integration status
discord summary     # Send scan activity summary
discord clear       # Clear scan history
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
