import nmap

def scan_network(network_range="192.168.1.11/24"):
    # Inicializa o scanner
    nm = nmap.PortScanner()
    
    print(f"Scanning network: {network_range}")
    
    # Realiza o escaneamento
    nm.scan(hosts=network_range, arguments='-sn')  # -sn: Scan apenas para descoberta de hosts
    
    devices = []
    
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            device = {
                "ip_address": nm[host]['addresses'].get('ipv4', 'Unknown'),
                "mac_address": nm[host]['addresses'].get('mac', 'Unknown'),
                "vendor": nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown')
            }
            devices.append(device)
    
    return devices

# Testando o script
if __name__ == "__main__":
    network_range = "192.168.1.0/24"  # Altere de acordo com sua rede local
    devices = scan_network(network_range)
    for device in devices:
        print(f"IP: {device['ip_address']}, MAC: {device['mac_address']}, Vendor: {device['vendor']}")
