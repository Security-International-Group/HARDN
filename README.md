# HARDN 

**Linux Security Hardening Framework**

This is a simplified demo version of HARDN, showcasing core security hardening capabilities for Debian-based Linux systems.

## Features

This demo version includes:

- **Security Scanners**: Lynis, AIDE, Legion integration
- **Network Security**: Fail2ban, Suricata support
- **System Hardening**: Basic security configurations
- **Modular Architecture**: Extensible tool and module system

## Installation

```bash
# Clone the repository
git clone https://github.com/Security-International-Group/HARDN.git
cd HARDN

# Build the package
make build

# Install the package
sudo dpkg -i hardn_*.deb
```

## Usage

```bash
# Display help
hardn --help

# List available tools
hardn --list-tools

# List available modules  
hardn --list-modules

# Run a specific tool
hardn --tool lynis
```

## Note

This is a demonstration version with limited features. For enterprise security requirements, please contact Security International Group for the full HARDN-XDR solution.

## License

MIT License - See LICENSE file for details
