import os
import psutil
import time
import json
import requests
import subprocess
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from cryptography.fernet import Fernet
import boto3
import syslog

LOG_FILE = "./fortress_logs.txt"  # File to log security events
MONITORED_PORTS = [22, 80, 443]  # Critical ports to monitor
ALERT_THRESHOLD = 10             # Max connection attempts before blocking
THREAT_INTELLIGENCE_API_KEY = "YOUR_ABUSEIPDB_API_KEY"  # Example API key
CRITICAL_FILES = ["/etc/passwd", "/etc/shadow", "/var/log/auth.log"]
AWS_REGION = "us-east-1"  # AWS region for GuardDuty checks

def log_event(event):
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} - {event}\n")
    print(f"[LOGGED]: {event}")

def configure_firewall():
    print("[*] Configuring firewall...")
    os.system("iptables -F")
    os.system("iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
    os.system("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
    os.system("iptables -A INPUT -p tcp --dport 443 -j ACCEPT")
    os.system("iptables -A INPUT -j DROP")
    log_event("Firewall configured: Allowed ports 22, 80, 443. All else blocked.")

def block_ip(ip):
    print(f"[!] Blocking malicious IP: {ip}")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    log_event(f"IP blocked: {ip}")

def check_integrity():
    print("[*] Checking system integrity...")
    for file in CRITICAL_FILES:
        if not os.path.exists(file):
            log_event(f"WARNING: Critical file missing: {file}")
        else:
            log_event(f"Integrity check passed for: {file}")

def train_anomaly_model(training_data):
    model = IsolationForest()
    model.fit(training_data)
    return model

def detect_anomalies(model, new_traffic_data):
    prediction = model.predict(new_traffic_data)
    return prediction

def check_ip_abuse(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": THREAT_INTELLIGENCE_API_KEY}
    params = {"ipAddress": ip}
    response = requests.get(url, params=params, headers=headers)
    data = response.json()
    if data["data"]["abuseConfidenceScore"] > 80:
        print(f"Malicious IP detected: {ip}")
        block_ip(ip)

def train_ueba_model(user_data):
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(user_data)
    model = OneClassSVM(gamma='auto')
    model.fit(data_scaled)
    return model

def detect_abnormal_behavior(model, user_activity):
    prediction = model.predict([user_activity])
    if prediction == -1:
        print("Abnormal behavior detected! Take action.")
        
def send_log_to_siem(message):
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL1)
    syslog.syslog(syslog.LOG_INFO, message)
    print(f"Log sent to SIEM: {message}")

def handle_brute_force_attack(ip):
    print(f"Blocking IP {ip} due to brute force attack.")
    block_ip(ip)
    send_alert_email("Brute Force Attack Detected", f"Blocked IP: {ip} after multiple failed attempts.")
    
def rate_limit_ssh():
    os.system("sudo iptables -A INPUT -p tcp --dport 22 -m limit --limit 1/s -j ACCEPT")
    log_event("Rate limiting applied to SSH connections.")

def run_zeek_on_traffic(pcap_file):
    subprocess.run(["zeek", "-r", pcap_file])

def encrypt_logs(logs):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_logs = cipher_suite.encrypt(logs.encode())
    return encrypted_logs

def save_encrypted_logs(encrypted_logs):
    with open("encrypted_logs.txt", "wb") as f:
        f.write(encrypted_logs)

def check_aws_guardduty_findings():
    client = boto3.client('guardduty', region_name=AWS_REGION)
    findings = client.list_findings()
    if findings:
        print("GuardDuty Findings: ", findings)
    else:
        print("No findings in GuardDuty.")

def monitor_intrusions():
    print("[*] Monitoring system for intrusion attempts...")
    connection_attempts = {}
    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "SYN_RECV" and conn.laddr.port in MONITORED_PORTS:
                ip = conn.raddr.ip
                connection_attempts[ip] = connection_attempts.get(ip, 0) + 1
                if connection_attempts[ip] > ALERT_THRESHOLD:
                    block_ip(ip)
                    log_event(f"Blocked IP {ip} after {ALERT_THRESHOLD} attempts.")
        time.sleep(5)

if __name__ == "__main__":
    print("FORTRESS FRAMEWORK ACTIVATED")
    log_event("Defense system initiated.")
    
    configure_firewall()
    
    check_integrity()
    
    training_data = np.array([[192, 22, 'tcp', 5], [192, 80, 'tcp', 3]])
    model = train_anomaly_model(training_data)
    new_traffic_data = np.array([[192, 22, 'tcp', 10]])
    anomalies = detect_anomalies(model, new_traffic_data)
    if -1 in anomalies:
        print("Anomaly detected! Take action.")
    
    monitor_intrusions()

    check_ip_abuse("192.168.1.1")
    
    user_data = [[3, 5], [10, 10], [15, 5]]  # Example: login count, resources accessed
    model = train_ueba_model(user_data)
    user_activity = [20, 5]  # Example new data
    detect_abnormal_behavior(model, user_activity)
    
    send_log_to_siem("Firewall rule configured: Allowed port 80.")
    
    rate_limit_ssh()

    check_aws_guardduty_findings()
    
    logs = "Critical log message"
    encrypted_logs = encrypt_logs(logs)
    save_encrypted_logs(encrypted_logs)
    
    run_zeek_on_traffic("network_traffic.pcap")