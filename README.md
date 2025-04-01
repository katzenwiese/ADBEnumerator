# ADBEnumerator

ADBEnumerator is a multi-threaded Python tool for scanning and gathering information from Android Debug Bridge (ADB)-enabled devices over a network. It supports subnet scanning, IP list scanning, and organizes results by device architecture.

## Features
- Multi-threaded scanning using `ThreadPoolExecutor`
- Validates ADB devices using crafted handshake
- Collects detailed device information (`getprop`, CPU architecture, etc.)
- Saves results in organized folders by architecture and IP
- Supports scanning of individual IPs, subnets (CIDR notation), and IP lists from files
- Supports retries and timeouts for improved reliability

## Requirements
- Python 3.x
- ADB (`adb` command must be available in your system's PATH)

## Installation
1. Install Python 3.x from [Python's official website](https://www.python.org/).
2. Install ADB via Android SDK Platform Tools or your system's package manager.
3. Clone this repository:
```bash
$ git clone <repository-url>
$ cd adb-scanner
```
4. Install dependencies (if any):
```bash
$ pip install -r requirements.txt  # If you add any dependencies later
```

## Usage
```
python3 adb_scanner.py [-h] [-ip IPADDRESS] [-f FILE] [-t THREADS]
```

### Arguments:
- `-ip`, `--ipaddress`: IP address or subnet (CIDR) to scan.
- `-f`, `--file`: File with a list of IPs to scan (one IP per line).
- `-t`, `--threads`: Number of threads to use (default: 20).

### Examples:

- Scan a single IP:
```bash
python3 adb_scanner.py -ip 192.168.1.10
```

- Scan a subnet:
```bash
python3 adb_scanner.py -ip 192.168.1.0/24
```

- Scan from a file of IP addresses:
```bash
python3 adb_scanner.py -f ips.txt
```

## Output
Results are stored in the `adb_scan_results` directory, organized by architecture and IP address.

Example:
```
adb_scan_results/
├── arm64-v8a
│   ├── 192.168.1.10
│   │   ├── model.txt
│   │   ├── product_name.txt
│   │   ├── cpu_cores.txt
│   │   └── getprop_dump.txt
└── unknown
    ├── 192.168.1.15
    │   ├── model.txt
    │   ├── product_name.txt
    │   ├── cpu_cores.txt
    │   └── getprop_dump.txt
```

## License
This project is licensed under the MIT License.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer
This tool is intended for authorized testing and educational purposes only. Usage of this tool without proper authorization is illegal and unethical.

