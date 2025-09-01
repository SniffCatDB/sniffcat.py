import paramiko
import socket
import threading
import json
import requests
import subprocess
from datetime import datetime
from sniffcat import SniffCatClient  # SniffCat import

LOG_FILE = 'ssh_login_attempts.log'
HOST_KEY = paramiko.RSAKey.generate(2048)
PORTS = [22]  # 🚨 tylko port 22

# Init SniffCat client
SNIFFCAT_API_TOKEN = "your_api_token_here"
client = SniffCatClient(SNIFFCAT_API_TOKEN)

def log_attempt(attempt):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(json.dumps(attempt) + '\n')

def get_geolocation(ip):
    url = f'http://ip-api.com/json/{ip}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        print(f'Error fetching geolocation data: {e}')
    return {}

def report_to_sniffcat(ip, comment="SSH login attempt detected"):
    try:
        result = client.report_ip_port_scan(ip, comment=comment)
        print(f"Reported IP {ip} to SniffCat: {result}")
    except Exception as e:
        print(f"Failed to report IP {ip} to SniffCat: {e}")

def ban_ip_forever(ip):
    # Sprawdź czy IP już nie jest zbanowane
    check_command = f'iptables -C INPUT -s {ip} -j DROP'
    ban_command = f'iptables -A INPUT -s {ip} -j DROP'
    try:
        subprocess.run(check_command, shell=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f'IP {ip} już jest zbanowane.')
    except subprocess.CalledProcessError:
        try:
            subprocess.run(ban_command, shell=True, check=True)
            print(f'Permanently banned IP {ip} successfully.')
        except subprocess.CalledProcessError as e:
            print(f'Failed to ban IP {ip}: {e}')

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        self.username = ""
        self.password = ""
    
    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        return 'password'

def handle_connection(client_sock, addr):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    server = FakeSSHServer(addr)
    
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is not None:
            channel.send("Login attempt recorded. Thank you.\n")
            channel.close()
    except (paramiko.SSHException, UnicodeDecodeError, EOFError, TimeoutError):
        attempt = {
            'ip': addr[0],
            'error': 'SSH protocol error',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_sniffcat(addr[0], comment="SSH protocol error / suspicious activity")
        threading.Thread(target=ban_ip_forever, args=(addr[0],)).start()
        transport.close()
        return

    attempt = {
        'ip': addr[0],
        'username': server.username,
        'password': server.password,
        'geolocation': get_geolocation(addr[0]),
        'timestamp': datetime.utcnow().isoformat()
    }

    log_attempt(attempt)
    report_to_sniffcat(addr[0], comment=f"SSH login attempt with user={server.username}, pass={server.password}")
    threading.Thread(target=ban_ip_forever, args=(addr[0],)).start()
    transport.close()

def start_server(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        print(f'Starting SSH honeypot on port {port}')

        while True:
            client_sock, addr = sock.accept()
            print(f'Connection from {addr}')
            threading.Thread(target=handle_connection, args=(client_sock, addr)).start()
    except OSError as e:
        if e.errno == 98:
            print(f'Port {port} is already in use. Skipping...')
        else:
            print(f'Failed to start server on port {port}: {e}')

if __name__ == "__main__":
    threads = []
    for port in PORTS:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
