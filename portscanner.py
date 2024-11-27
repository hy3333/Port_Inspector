from socket import *
import time
import threading
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
import re
from urllib.parse import urlparse
import os

# Common services mapped to their respective ports
common_services = {
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP (Server)',
    68: 'DHCP (Client)',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP (Network News Transfer Protocol)',
    123: 'NTP (Network Time Protocol)',
    135: 'Microsoft RPC',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP',
    161: 'SNMP (Simple Network Management Protocol)',
    162: 'SNMPTRAP',
    179: 'BGP (Border Gateway Protocol)',
    194: 'IRC (Internet Relay Chat)',
    443: 'HTTPS',
    445: 'SMB (Server Message Block)',
    465: 'SMTPS (Secure SMTP)',
    502: 'Modbus (Industrial control systems)',
    514: 'Syslog',
    515: 'LPD (Line Printer Daemon)',
    993: 'IMAPS (Secure IMAP)',
    995: 'POP3S (Secure POP3)',
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1433: 'Microsoft SQL Server',
    1434: 'Microsoft SQL Monitor',
    1521: 'Oracle Database',
    1723: 'PPTP (Point-to-Point Tunneling Protocol)',
    1812: 'RADIUS (Authentication)',
    1813: 'RADIUS (Accounting)',
    2049: 'NFS (Network File System)',
    3306: 'MySQL',
    3389: 'RDP (Remote Desktop Protocol)',
    3690: 'SVN (Subversion)',
    5432: 'PostgreSQL',
    5900: 'VNC (Virtual Network Computing)',
    5985: 'Windows Remote Management',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS (Alternative)',
    9000: 'SonarQube',
    9090: 'Prometheus',
    9200: 'Elasticsearch',
    11211: 'Memcached',
    27017: 'MongoDB',
    50000: 'SAP (System Applications and Products)',
    50070: 'Hadoop NameNode',

}


console = Console()


def validate_target(target):
    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"  

    try:
        # Check if the input is a valid IP address or hostname
        if target.startswith(('http://', 'https://', 'ftp://', 'ssh://')):  
            target = urlparse(target).hostname  
        # Now check if it's an IP address or a valid domain name
        gethostbyname(target)  # Will throw exception if DNS resolution fails
        if not re.match(ip_regex, target):  # Check if it's an IP address
            return True  # Valid hostname or IP
        else:
            return True  # It's a valid IP address
    except gaierror:
        console.print(f"[bold red]Error:[/bold red] DNS resolution failed for '{target}'. Please enter a valid host.")
        return False
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] '{target}' is not a valid hostname or IP address.")
        return False


def validate_port_range():
    while True:
        try:
            port_range = input("Enter port range (e.g., 20-80): ")
            if '-' not in port_range:
                raise ValueError("Invalid port range format. Use 'start-end' (e.g., 20-80).")
            start_port, end_port = port_range.split('-')
            if not (start_port.isdigit() and end_port.isdigit()):
                raise ValueError("Port range must be numeric.")
            
            start_port, end_port = int(start_port), int(end_port)
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                raise ValueError("Ports must be between 0 and 65535.")
            if start_port > end_port:
                raise ValueError("Start port cannot be greater than end port.")
            
            return start_port, end_port
        except ValueError as ve:
            console.print(f"[bold red]Error:[/bold red] {ve}\n")
            console.print("[bold yellow]Please enter valid port range.[/bold yellow]\n")


def scan_port(t_ip, port, results, progress_bar):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(1)
        conn = s.connect_ex((t_ip, port))
        if conn == 0:  
            service = common_services.get(port, "Unknown Service")
            results.append((port, "OPEN", service))
        s.close()
    except PermissionError:
        results.append((port, "ERROR", "Permission Denied"))
    except Exception as e:
        results.append((port, "ERROR", str(e)))
    finally:
        progress_bar.update(1)


def save_results_to_file(results, target):
    try:
        # Replace invalid characters in the target to create a valid file name
        valid_file_name = re.sub(r'[^\w\-_\. ]', '_', target)  
        file_name = f"{valid_file_name}_scan_results.txt"

        # Determine the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_directory, file_name)

        # Write results to the file
        with open(file_path, 'w') as f:
            for result in results:
                f.write(f"Port {result[0]}: {result[1]} - {result[2]}\n")
        
        console.print(f"\n[bold green]Scan results saved to '{file_path}'.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error while saving results:[/bold red] {e}")



if __name__ == "__main__":
    starttime = time.time()  # Capture the start time here


    try:
        # Legal usage disclaimer
        console.print("[bold red]WARNING:[/bold red] Use this tool only on systems you own or have explicit permission to scan.")
        console.print("[bold yellow]By proceeding, you confirm that you have the necessary authorization.[/bold yellow]\n")
        
       
        target = input('Enter host for scanning: ')

        # Validate target (host) until it's correct
        while not validate_target(target):
            target = input('Enter host for scanning: ')

       
        t_ip = gethostbyname(target)
        console.print(f"\n[bold green]Starting scan on host:[/bold green] {t_ip}\n")

        
        start_port, end_port = validate_port_range()

        threads = []
        results = []

        # Set up progress indicator
        total_ports = end_port - start_port + 1
        progress_bar = tqdm(total=total_ports, desc="Scanning Ports", unit="port")
        
        # Scanning each port in the specified range using multithreading
        for i in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(t_ip, i, results, progress_bar))
            threads.append(t)
            t.start()

        # Join all threads to wait for their completion
        for t in threads:
            t.join()

        progress_bar.close()

       
        table = Table(title="Port Scan Results")
        table.add_column("Port", justify="right")
        table.add_column("Status", justify="center")
        table.add_column("Service", justify="left")

        for result in results:
            table.add_row(str(result[0]), result[1], result[2])

        console.print(table)

     
        save_results_to_file(results, target)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    
    
    print(f"\nTime taken: {time.time() - starttime:.2f} seconds")
