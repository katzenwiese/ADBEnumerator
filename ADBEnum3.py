#!/usr/bin/env python3

import os
import subprocess
import socket
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


class ADBScanner:
    def __init__(self):
        self.results_dir = "adb_scan_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.valid_architectures = [
            "armeabi",
            "armeabi-v7a",
            "arm64-v8a",
            "x86",
            "x86_64",
            "mips",
            "mips64"
        ]

    def log(self, message):
        print(f"[ADB Scanner] {message}")

    def retrieve(self, ip, timeout=5):
        """
        Validate if the device speaks ADB protocol on port 5555 using a crafted handshake.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((str(ip), 5555))
            sock.send(b"\x43\x4e\x58\x4e\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1\x68\x6f\x73\x74\x3a\x3a\x00")
            data = sock.recv(2048)
            sock.close()
            return data.decode('utf-8', 'ignore')
        except Exception:
            return None

    def adb_command(self, ip, command, timeout=10):
        """
        Run adb command on specific IP address.
        """
        try:
            result = subprocess.run(
                ["adb", "-s", f"{ip}:5555", "shell", command],
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            self.log(f"[!] Error running adb command on {ip}: {e}")
            return ""

    def organize_device(self, ip, architecture, data_dict):
        """
        Save gathered device data into organized folders.
        """
        arch = architecture if architecture else "unknown"
        device_dir = os.path.join(self.results_dir, arch, ip)
        os.makedirs(device_dir, exist_ok=True)

        for filename, content in data_dict.items():
            file_path = os.path.join(device_dir, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

    def validate_architecture(self, arch):
        """
        Check if the architecture is valid and known, else classify as 'unknown'.
        """
        if arch in self.valid_architectures:
            return arch
        return "unknown"

    def handle_device(self, ip):
        """
        Handle scanning, connection, data gathering, and disconnection for a single device.
        """
        self.log(f"Scanning {ip}")

        # Step 1: Validate ADB handshake
        response = self.retrieve(ip)
        if not response or ("device" not in response and "product" not in response):
            self.log(f"[!] {ip} does NOT appear to be a valid ADB device. Skipping.")
            return
        self.log(f"[+] {ip} responded as a valid ADB device. Continuing...")

        # Step 2: Connect to the device
        subprocess.run(["adb", "connect", f"{ip}:5555"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Step 3: Confirm connection is alive using echo ping
        shell_check = self.adb_command(ip, 'echo "ping"')
        if "ping" not in shell_check:
            self.log(f"[!] {ip} failed to maintain ADB shell session. Skipping.")
            subprocess.run(["adb", "disconnect", f"{ip}:5555"], stdout=subprocess.DEVNULL)
            return

        # Step 4: Get architecture and validate
        raw_arch = self.adb_command(ip, "getprop ro.product.cpu.abi").strip()
        arch = self.validate_architecture(raw_arch)
        self.log(f"[+] Architecture detected: {raw_arch if raw_arch else 'None'} | Used for sorting: {arch}")

        # Step 5: Collect detailed device information
        model = self.adb_command(ip, "getprop ro.product.model") or "Unknown"
        product_name = self.adb_command(ip, "getprop ro.product.name") or "Unknown"

        # Safer way to count CPU cores
        cpu_info = self.adb_command(ip, "grep '^processor' /proc/cpuinfo")
        cpu_cores = str(len(cpu_info.strip().splitlines())) if cpu_info else "Unknown"

        full_props = self.adb_command(ip, "getprop") or "Unavailable"

        # Step 6: Save all collected data
        data_to_store = {
            "model.txt": model,
            "product_name.txt": product_name,
            "cpu_cores.txt": cpu_cores,
            "getprop_dump.txt": full_props
        }
        self.organize_device(ip, arch, data_to_store)

        self.log(f"[+] Device {ip} scanned and data saved (Arch: {arch}).")

        # Step 7: Disconnect from the device
        subprocess.run(["adb", "disconnect", f"{ip}:5555"], stdout=subprocess.DEVNULL)

    def scan_ip_list(self, ip_list, threads=20):
        """
        Multi-threaded scanning from list of IPs.
        """
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.handle_device, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log(f"[!] Error scanning {ip}: {e}")

    def scan_subnet(self, subnet, threads=20):
        """
        Parse and scan subnet range.
        """
        network = ipaddress.ip_network(subnet, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        self.scan_ip_list(ip_list, threads)

    def scan_from_file(self, file_path, threads=20):
        """
        Scan IPs listed in a file.
        """
        if not os.path.exists(file_path):
            self.log(f"[!] File {file_path} not found.")
            return

        with open(file_path, "r") as f:
            ip_list = [line.strip() for line in f if line.strip()]
        self.scan_ip_list(ip_list, threads)

    def main(self):
        """
        Argument parsing and entry point.
        """
        print("====== ADB Scanner Starting ======")
        parser = argparse.ArgumentParser(description="Efficient ADB Device Scanner with Validation")
        parser.add_argument('-ip', '--ipaddress', help="IP address or subnet (CIDR) to scan")
        parser.add_argument('-f', '--file', help="File with list of IPs to scan")
        parser.add_argument('-t', '--threads', type=int, default=20, help="Number of threads (default: 20)")
        args = parser.parse_args()

        if args.ipaddress:
            if '/' in args.ipaddress:
                self.scan_subnet(args.ipaddress, args.threads)
            else:
                self.scan_ip_list([args.ipaddress], args.threads)
        elif args.file:
            self.scan_from_file(args.file, args.threads)
        else:
            parser.print_help()


if __name__ == "__main__":
    ADBScanner().main()
