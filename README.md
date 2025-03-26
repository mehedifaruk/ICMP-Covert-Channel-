# ICMP Covert Channel 🕵️‍♂️🌐

## Overview
A stealthy communication mechanism designed to transmit encrypted messages through non-standard ICMP packets, bypassing traditional network monitoring and firewall restrictions.

## Scenario 🔒
In environments with strict firewall policies that allow only specific ICMP packet types for network debugging, this implementation leverages ICMP Type 47 (a reserved type) to create a covert communication channel with robust encryption.

## Key Features ✨
- **Stealth Communication**: Utilizes non-standard ICMP Type 47 packets
- **Strong Encryption**: AES-256-CBC encryption
- **Data Integrity**: HMAC-SHA256 authentication
- **Flexible Deployment**: Configurable salt and passphrase

## Components 🧩

### Client Program (`client.py`)
- 🖥️ Sends encrypted messages using custom ICMP Type 47 packets
- 📥 Accepts plaintext input from keyboard
- 🎯 Transmits to specified IP address
- 🔐 Encrypts payload with user-provided passphrase

### Server Program (`server.py`)
- 👂 Listens for incoming ICMP Type 47 packets
- 🔓 Decrypts received messages
- 📝 Prints decrypted plaintext to console

## Technical Details 🛠️
- **Encryption**: AES-256-CBC with PKCS7 padding
- **Key Derivation**: SHA-256 based key generation
- **Authentication**: HMAC-SHA256
- **Packet Handling**: Custom checksum verification

## Prerequisites 🔧
- Python 3.x
- `cryptography` `socket` `struct` `sys` `collections` `argparse` `getpass`  library
- Root/Administrator privileges
- Compatible network environment

## Usage 🚀

### Client
```bash
sudo python3 client.py <destination_ip>
```

### Server
```bash
sudo python3 server.py
```

## Security Considerations ⚠️
- Requires shared secret passphrase
- Uses non-standard network communication
- Potential detection by advanced network monitoring

## Disclaimer 📝
This tool is for educational and research purposes only. Unauthorized network interception may be illegal.

## License 📄
MIT

## Contributing 🤝
Contributions, issues, and feature requests are welcome!


