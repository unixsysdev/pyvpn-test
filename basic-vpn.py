import socket
import fcntl
import struct
import os
import logging
import json
import time
import subprocess
import argparse
from threading import Thread
import nacl.public
import traceback

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

MTU = 1500
SOCKET_PATH = "/tmp/vpn.sock"

def hex_dump(data, prefix=''):
    """Print hex dump of packet data"""
    for i in range(0, len(data), 16):
        hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
        logger.debug(f"{prefix}{hex_str:48s}  {ascii_str}")

def decode_ip_packet(data):
    """Decode and log IP packet information"""
    if len(data) < 20:
        return "Invalid IP packet (too short)"
    
    version = (data[0] >> 4) & 0xF
    ihl = data[0] & 0xF
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocols.get(protocol, str(protocol))
    
    return f"IPv{version} {protocol_name} {src_ip} -> {dst_ip}"

def create_tun(name):
    logger.debug(f"Creating TUN interface: {name}")
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    logger.debug(f"TUN interface {name} created successfully")
    return tun

def configure_tun(name, ip):
    logger.debug(f"Configuring TUN interface {name} with IP {ip}")
    try:
        subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", name], check=True)
        subprocess.run(["ip", "link", "set", "up", "dev", name], check=True)
        logger.debug(f"TUN interface {name} configured successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to configure TUN interface: {e}")
        raise

class VPNServer:
    def __init__(self, host, port):
        self.is_local = host in ('localhost', '127.0.0.1')
        self.host = host
        self.port = port
        logger.info(f"Starting VPN Server - Mode: {'Local' if self.is_local else 'Remote'}")
        
        self.private_key = nacl.public.PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.clients = {}
        
        # Create interface
        self.interface = "vpn0"
        self.tun = create_tun(self.interface)
        configure_tun(self.interface, "10.0.0.1")
        
        # Enable forwarding and NAT if not local
        if not self.is_local:
            logger.debug("Configuring forwarding and NAT")
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            subprocess.run([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-s", "10.0.0.0/24", "-j", "MASQUERADE"
            ])
        
        # Setup communication socket
        if self.is_local:
            logger.debug(f"Setting up Unix domain socket at {SOCKET_PATH}")
            try:
                os.unlink(SOCKET_PATH)
            except FileNotFoundError:
                pass
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.sock.bind(SOCKET_PATH)
            # Set proper permissions for the socket
            os.chmod(SOCKET_PATH, 0o777)
        else:
            logger.debug(f"Setting up UDP socket on {host}:{port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((host, port))

    def trace_packet(self, data, direction, is_encrypted=False):
        """Log detailed packet information"""
        if len(data) < 20:
            logger.debug(f"Packet too short: {len(data)} bytes")
            return

        logger.debug(f"\n{'='*60}")
        logger.debug(f"Packet {direction} - Length: {len(data)} bytes")

        if not is_encrypted:
            version = (data[0] >> 4) & 0xF
            ihl = data[0] & 0xF
            protocol = data[9]
            src_ip = socket.inet_ntoa(data[12:16])
            dst_ip = socket.inet_ntoa(data[16:20])

            protocols = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }
            protocol_name = protocols.get(protocol, f"Unknown({protocol})")

            logger.debug(f"IP Version: {version}")
            logger.debug(f"Protocol: {protocol_name}")
            logger.debug(f"Source IP: {src_ip}")
            logger.debug(f"Destination IP: {dst_ip}")

            if protocol == 1:  # ICMP
                if len(data) >= 28:  # Minimum ICMP echo size
                    icmp_type = data[20]
                    icmp_code = data[21]
                    logger.debug(f"ICMP Type: {icmp_type} (8=echo request, 0=echo reply)")
                    logger.debug(f"ICMP Code: {icmp_code}")

        logger.debug("Packet data:")
        hex_dump(data, '  ')
        logger.debug('='*60)


    def handle_clients(self):
        logger.info("Starting client handler")
        while True:
            try:
                logger.debug("Waiting for client data...")
                data, addr = self.sock.recvfrom(MTU)
                logger.debug(f"Received {len(data)} bytes from {addr}")
                
                if self.is_local and not addr:
                    logger.debug("Local connection with no address, using socket path")
                    addr = SOCKET_PATH
                
                if addr not in self.clients:
                    # New client
                    logger.info(f"New client connection from {addr}")
                    try:
                        client_key = nacl.public.PublicKey(data)
                        box = nacl.public.Box(self.private_key, client_key)
                        next_ip = f"10.0.0.{len(self.clients) + 2}"
                        self.clients[addr] = {
                            'box': box,
                            'ip': next_ip,
                            'connected_at': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                        
                        response = {
                            'public_key': bytes(self.public_key).hex(),
                            'ip': next_ip
                        }
                        response_data = json.dumps(response).encode()
                        logger.debug(f"Sending response to {addr}: {response}")
                        
                        if self.is_local:
                            logger.debug("Using Unix socket for response")
                            client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                            client_sock.sendto(response_data, addr)
                            client_sock.close()
                        else:
                            self.sock.sendto(response_data, addr)
                            
                        logger.info(f"Client {addr} assigned IP: {next_ip}")
                    except Exception as e:
                        logger.error(f"Error handling new client: {e}")
                        logger.error(traceback.format_exc())
                else:
                    # Existing client
                    try:
                        box = self.clients[addr]['box']
                        decrypted = box.decrypt(data)
                        os.write(self.tun, decrypted)
                        logger.debug(f"Processed {len(data)} bytes from client {addr}")
                    except Exception as e:
                        logger.error(f"Error processing client data: {e}")
                        logger.error(traceback.format_exc())
            
            except Exception as e:
                logger.error(f"Error in client handler: {e}")
                logger.error(traceback.format_exc())

    def handle_tun(self):
        logger.info("Starting TUN handler")
        while True:
            try:
                data = os.read(self.tun, MTU)
                dst_ip = socket.inet_ntoa(data[16:20])
                logger.debug(f"Read {len(data)} bytes from TUN, destination IP: {dst_ip}")
                
                for addr, client in self.clients.items():
                    if client['ip'] == dst_ip:
                        try:
                            encrypted = client['box'].encrypt(data)
                            if self.is_local:
                                client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                                client_sock.sendto(encrypted, addr)
                                client_sock.close()
                            else:
                                self.sock.sendto(encrypted, addr)
                            logger.debug(f"Sent {len(encrypted)} bytes to {addr}")
                        except Exception as e:
                            logger.error(f"Error sending to client {addr}: {e}")
                        break
            except Exception as e:
                logger.error(f"Error in TUN handler: {e}")
                logger.error(traceback.format_exc())

    def run(self):
        Thread(target=self.handle_clients, daemon=True).start()
        Thread(target=self.handle_tun, daemon=True).start()
        try:
            logger.info("VPN Server running")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.is_local:
                try:
                    os.unlink(SOCKET_PATH)
                except:
                    pass

class VPNClient:
    def __init__(self, host, port):
        self.is_local = host in ('localhost', '127.0.0.1')
        self.host = host
        self.port = port
        logger.info(f"Starting VPN Client - Mode: {'Local' if self.is_local else 'Remote'}")
        
        self.private_key = nacl.public.PrivateKey.generate()
        self.public_key = self.private_key.public_key
        
        # Setup communication socket
        if self.is_local:
            logger.debug("Setting up Unix domain socket for client")
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.server_addr = SOCKET_PATH
            # Bind to a temporary path for receiving responses
            self.client_path = f"{SOCKET_PATH}_client"
            try:
                os.unlink(self.client_path)
            except FileNotFoundError:
                pass
            self.sock.bind(self.client_path)
            os.chmod(self.client_path, 0o777)
        else:
            logger.debug(f"Setting up UDP socket to connect to {host}:{port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_addr = (host, port)
        
        # Create interface
        self.interface = "vpn1"
        self.tun = create_tun(self.interface)

    def connect(self):
        try:
            logger.info("Initiating connection to server")
            # Send public key
            logger.debug("Sending public key")
            self.sock.sendto(bytes(self.public_key), self.server_addr)
            
            # Get response
            logger.debug("Waiting for server response")
            data = self.sock.recvfrom(MTU)[0]
            logger.debug(f"Received {len(data)} bytes from server")
            
            response = json.loads(data.decode())
            logger.debug(f"Server response: {response}")
            
            # Setup crypto
            server_key = nacl.public.PublicKey(bytes.fromhex(response['public_key']))
            self.box = nacl.public.Box(self.private_key, server_key)
            
            # Configure interface
            configure_tun(self.interface, response['ip'])
            if not self.is_local:
                logger.debug("Adding default route through VPN")
                subprocess.run(["ip", "route", "add", "default", "dev", self.interface])
            
            logger.info("Connection established successfully")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            logger.error(traceback.format_exc())
            return False

        if self.connect_to_server():
            logger.info("Connection established, running tests...")
            time.sleep(2)  # Give time for routes to settle
            return self.test_connection()
        return False

    def trace_packet(self, data, direction, is_encrypted=False):
        """Log detailed packet information"""
        logger.debug(f"\n{'='*60}")
        logger.debug(f"Packet {direction} - Length: {len(data)} bytes")
        if is_encrypted:
            logger.debug("Encrypted packet data:")
            hex_dump(data, '  ')
        else:
            logger.debug(decode_ip_packet(data))
            logger.debug("Packet data:")
            hex_dump(data, '  ')
        logger.debug('='*60)

    def cleanup(self):
        logger.info("Cleaning up client resources")
        if self.is_local:
            try:
                os.unlink(self.client_path)
            except:
                pass


    def run(self):
        if not self.connect():
            return
        
        Thread(target=self.handle_tun, daemon=True).start()
        Thread(target=self.handle_server, daemon=True).start()
        
        try:
            # Wait a moment for everything to initialize
            time.sleep(2)
            # Run the test
            self.test_vpn()
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.cleanup()

    def handle_tun(self):
        logger.info("Starting TUN handler")
        while True:
            try:
                data = os.read(self.tun, MTU)
                self.trace_packet(data, "Client -> Server", is_encrypted=False)
                encrypted = self.box.encrypt(data)
                self.sock.sendto(encrypted, self.server_addr)
                logger.debug(f"Sent {len(encrypted)} bytes to server")
            except Exception as e:
                logger.error(f"Error in TUN handler: {e}")
                logger.error(traceback.format_exc())

    def handle_server(self):
        logger.info("Starting server handler")
        while True:
            try:
                encrypted_data = self.sock.recvfrom(MTU)[0]
                decrypted = self.box.decrypt(encrypted_data)
                self.trace_packet(decrypted, "Server -> Client", is_encrypted=False)
                os.write(self.tun, decrypted)
                logger.debug(f"Processed {len(encrypted_data)} bytes from server")
            except Exception as e:
                logger.error(f"Error in server handler: {e}")
                logger.error(traceback.format_exc())

    def test_connection(self):
        """Test the VPN connection"""
        logger.info("\nTesting VPN connection...")
        try:
            # Test with ping to Google DNS
            logger.info("Sending ping through VPN...")
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "5", "8.8.8.8"],
                capture_output=True,
                text=True
            )
            logger.info("Ping output:")
            logger.info(result.stdout)
            
            # Test DNS resolution
            logger.info("\nTesting DNS resolution through VPN...")
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "5", "google.com"],
                capture_output=True,
                text=True
            )
            logger.info("DNS resolution output:")
            logger.info(result.stdout)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Test failed: {e}")
            if e.stderr:
                logger.error(f"Error output: {e.stderr}")
            return False


    def test_vpn(self):
        """Execute a simple ping test through the VPN"""
        logger.info("\n=== Starting VPN Connection Test ===")
        try:
            # First test: ping Google DNS
            cmd = ["ping", "-c", "1", "-W", "2", "8.8.8.8", "-I", self.interface]
            logger.info(f"Running test: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            logger.info("Ping test output:")
            logger.info(result.stdout)
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Test failed: {e}")
            if e.stdout:
                logger.error(f"Output: {e.stdout}")
            if e.stderr:
                logger.error(f"Error: {e.stderr}")
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['server', 'client'], required=True)
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    
    try:
        if args.mode == 'server':
            VPNServer(args.host, args.port).run()
        else:
            VPNClient(args.host, args.port).run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())

if __name__ == '__main__':
    main()
