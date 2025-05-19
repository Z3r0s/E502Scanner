# E502 OSINT Terminal

An interactive OSINT (Open Source Intelligence) terminal tool written in Python. This tool provides various reconnaissance capabilities without relying on external APIs.

## Features

- DNS lookup and WHOIS information
- Reverse IP lookup
- Subdomain enumeration
- Data leak checking
- GitHub reconnaissance
- HTTP headers and SSL certificate analysis
- Port scanning
- Tor proxy support
- Beautiful terminal interface with rich formatting

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/E502-OSINT.git
cd E502-OSINT
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the tool:
```bash
python E502OSINT.py
```

### Available Commands

- `help` - Display available commands
- `banner` - Show the E502 banner
- `whoami` - Display system information
- `dns <domain>` - Perform DNS lookup
- `whois <domain/IP>` - Perform WHOIS lookup
- `reverseip <ip>` - Perform reverse IP lookup
- `subdomains <domain>` - Find subdomains
- `leaks <email/domain>` - Check for potential data leaks
- `github <username/domain>` - Perform GitHub reconnaissance
- `headers <domain/URL>` - Check HTTP headers
- `ssl <domain>` - Check SSL certificate
- `scan <domain/IP>` - Perform port scan
- `proxy` - Enable/disable Tor proxy
- `clear` - Clear the screen
- `exit`/`quit` - Exit the program

### Tor Proxy Support

The tool supports routing requests through Tor SOCKS5 proxy (default: 127.0.0.1:9050). To use this feature:

1. Install Tor on your system
2. Start the Tor service
3. Use the `proxy` command in the tool to enable/disable proxying

## Security Notice

This tool is for educational and legitimate security research purposes only. Always:
- Obtain proper authorization before scanning any systems
- Respect privacy and data protection laws
- Use responsibly and ethically

## Author

z3r0s / Error502

## License

This project is licensed under the MIT License - see the LICENSE file for details. 