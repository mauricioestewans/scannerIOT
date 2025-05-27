import nmap
import time
import json
import argparse
from prettytable import PrettyTable
from datetime import datetime
import socket
import csv
import os

class NetworkScannerPro:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = []
        self.scan_history = []
        
    def scan_network(self, network_range="192.168.1.0/24", scan_type='discovery', ports='1-1024', 
                    save_report=False, output_format='table', verbose=False):
        """
        Perform network scanning with various options
        
        Args:
            network_range (str): IP range to scan (e.g., '192.168.1.0/24')
            scan_type (str): Type of scan ('discovery', 'quick', 'full', 'vulnerability')
            ports (str): Port range to scan (e.g., '1-1000')
            save_report (bool): Whether to save the scan report
            output_format (str): Output format ('table', 'json', 'csv')
            verbose (bool): Show detailed scan information
            
        Returns:
            list: List of discovered devices with details
        """
        scan_args = self._get_scan_arguments(scan_type, ports)
        start_time = time.time()
        
        print(f"\n[+] Starting {scan_type} scan on {network_range} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if verbose:
            print(f"[*] Using scan arguments: {scan_args}")
        
        try:
            self.nm.scan(hosts=network_range, arguments=scan_args)
        except nmap.PortScannerError as e:
            print(f"[-] Scan error: {str(e)}")
            return []
        except Exception as e:
            print(f"[-] Unexpected error: {str(e)}")
            return []
        
        scan_duration = time.time() - start_time
        devices = self._parse_scan_results()
        
        if verbose:
            print(f"[*] Scan completed in {scan_duration:.2f} seconds")
            print(f"[*] Found {len(devices)} active devices")
        
        self.scan_results = devices
        self.scan_history.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'network_range': network_range,
            'scan_type': scan_type,
            'duration': f"{scan_duration:.2f} seconds",
            'devices_found': len(devices)
        })
        
        if save_report:
            self._save_scan_report(output_format)
        
        return devices
    
    def _get_scan_arguments(self, scan_type, ports):
        """Generate nmap arguments based on scan type"""
        scan_args = {
            'discovery': '-sn',  # Ping scan (host discovery only)
            'quick': f'-T4 -F {ports}',  # Quick scan
            'full': f'-sV -O -p {ports}',  # Full scan with version detection and OS fingerprinting
            'vulnerability': f'-sV --script vuln -p {ports}'  # Vulnerability scan
        }
        return scan_args.get(scan_type, '-sn')
    
    def _parse_scan_results(self):
        """Parse nmap scan results into structured data"""
        devices = []
        
        for host in self.nm.all_hosts():
            host_info = {
                'ip_address': self.nm[host]['addresses'].get('ipv4', 'Unknown'),
                'status': self.nm[host].get('status', {}).get('state', 'Unknown'),
                'hostname': self._get_hostname(self.nm[host]['addresses'].get('ipv4')),
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            if 'mac' in self.nm[host]['addresses']:
                host_info.update({
                    'mac_address': self.nm[host]['addresses'].get('mac', 'Unknown'),
                    'vendor': self.nm[host]['vendor'].get(self.nm[host]['addresses'].get('mac', ''), 'Unknown')
                })
            
            if 'tcp' in self.nm[host]:
                host_info['open_ports'] = []
                for port, port_info in self.nm[host]['tcp'].items():
                    host_info['open_ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    })
            
            devices.append(host_info)
        
        return devices
    
    def _get_hostname(self, ip_address):
        """Attempt to resolve hostname from IP"""
        if not ip_address or ip_address == 'Unknown':
            return 'Unknown'
        
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return 'Unknown'
    
    def _save_scan_report(self, output_format='table'):
        """Save scan results to a file"""
        if not self.scan_results:
            print("[-] No scan results to save")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"network_scan_{timestamp}"
        
        try:
            if output_format == 'json':
                filename += '.json'
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=4)
            elif output_format == 'csv':
                filename += '.csv'
                self._save_as_csv(filename)
            else:
                filename += '.txt'
                self._save_as_text(filename)
            
            print(f"[+] Scan report saved as {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {str(e)}")
    
    def _save_as_csv(self, filename):
        """Save results in CSV format"""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['ip_address', 'mac_address', 'vendor', 'hostname', 'status', 'open_ports']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for device in self.scan_results:
                row = device.copy()
                if 'open_ports' in row:
                    row['open_ports'] = ', '.join([str(p['port']) for p in row['open_ports']])
                writer.writerow(row)
    
    def _save_as_text(self, filename):
        """Save results in human-readable text format"""
        with open(filename, 'w') as f:
            f.write(f"Network Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n\n")
            
            for device in self.scan_results:
                f.write(f"IP Address: {device['ip_address']}\n")
                f.write(f"MAC Address: {device.get('mac_address', 'Unknown')}\n")
                f.write(f"Vendor: {device.get('vendor', 'Unknown')}\n")
                f.write(f"Hostname: {device.get('hostname', 'Unknown')}\n")
                f.write(f"Status: {device.get('status', 'Unknown')}\n")
                
                if 'open_ports' in device:
                    f.write("Open Ports:\n")
                    for port in device['open_ports']:
                        f.write(f"  - Port {port['port']}: {port['service']} ({port['state']})")
                        if port.get('product'):
                            f.write(f" - {port['product']}")
                            if port.get('version'):
                                f.write(f" v{port['version']}")
                        f.write("\n")
                f.write("\n" + "-"*50 + "\n\n")
    
    def display_results(self, output_format='table'):
        """Display scan results in the specified format"""
        if not self.scan_results:
            print("[-] No scan results to display")
            return
        
        if output_format == 'json':
            print(json.dumps(self.scan_results, indent=4))
        elif output_format == 'table':
            self._display_table()
        else:
            for device in self.scan_results:
                print("\nDevice Information:")
                print(f"IP Address: {device['ip_address']}")
                print(f"MAC Address: {device.get('mac_address', 'Unknown')}")
                print(f"Vendor: {device.get('vendor', 'Unknown')}")
                print(f"Hostname: {device.get('hostname', 'Unknown')}")
                print(f"Status: {device.get('status', 'Unknown')}")
                
                if 'open_ports' in device:
                    print("\nOpen Ports:")
                    table = PrettyTable()
                    table.field_names = ["Port", "State", "Service", "Product", "Version"]
                    for port in device['open_ports']:
                        table.add_row([
                            port['port'],
                            port['state'],
                            port['service'],
                            port.get('product', ''),
                            port.get('version', '')
                        ])
                    print(table)
                print("-"*50)
    
    def _display_table(self):
        """Display results in a formatted table"""
        if not any('mac_address' in device for device in self.scan_results):
            # Simple table for discovery scans
            table = PrettyTable()
            table.field_names = ["IP Address", "Hostname", "Status", "Last Seen"]
            for device in self.scan_results:
                table.add_row([
                    device['ip_address'],
                    device.get('hostname', 'Unknown'),
                    device.get('status', 'Unknown'),
                    device.get('last_seen', 'Unknown')
                ])
        else:
            # Detailed table for scans with MAC info
            table = PrettyTable()
            table.field_names = ["IP Address", "MAC Address", "Vendor", "Hostname", "Status"]
            for device in self.scan_results:
                table.add_row([
                    device['ip_address'],
                    device.get('mac_address', 'Unknown'),
                    device.get('vendor', 'Unknown'),
                    device.get('hostname', 'Unknown'),
                    device.get('status', 'Unknown')
                ])
        
        print(table)
    
    def display_scan_history(self):
        """Display history of scans performed"""
        if not self.scan_history:
            print("[-] No scan history available")
            return
        
        table = PrettyTable()
        table.field_names = ["Timestamp", "Network Range", "Scan Type", "Duration", "Devices Found"]
        for scan in self.scan_history:
            table.add_row([
                scan['timestamp'],
                scan['network_range'],
                scan['scan_type'],
                scan['duration'],
                scan['devices_found']
            ])
        
        print("\nScan History:")
        print(table)

def main():
    parser = argparse.ArgumentParser(description='Network Scanner Pro - Advanced network scanning tool')
    parser.add_argument('network_range', nargs='?', default='192.168.1.0/24',
                      help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--type', choices=['discovery', 'quick', 'full', 'vulnerability'],
                      default='discovery', help='Type of scan to perform')
    parser.add_argument('-p', '--ports', default='1-1024',
                      help='Port range to scan (for quick/full/vulnerability scans)')
    parser.add_argument('-o', '--output', choices=['table', 'json', 'csv', 'text'],
                      default='table', help='Output format')
    parser.add_argument('-s', '--save', action='store_true',
                      help='Save scan results to a file')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output')
    parser.add_argument('--history', action='store_true',
                      help='Show scan history')
    
    args = parser.parse_args()
    
    scanner = NetworkScannerPro()
    
    if args.history:
        scanner.display_scan_history()
        return
    
    print(f"""
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    
    Network Scanner Pro - Advanced Network Scanning Tool
    """)
    
    scanner.scan_network(
        network_range=args.network_range,
        scan_type=args.type,
        ports=args.ports,
        save_report=args.save,
        output_format=args.output,
        verbose=args.verbose
    )
    
    scanner.display_results(output_format=args.output)

if __name__ == "__main__":
    main()