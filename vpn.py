import socket
import traceback
import sys
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
import nacl.secret
import nacl.utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MTU = 1500

def remove_route_if_exists(subnet, device=None):
    """Remove a route if it exists"""
    try:
        # Check if route exists
        cmd = ["ip", "route", "show", subnet]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            # Route exists, remove it
            if device:
                subprocess.run(["ip", "route", "del", subnet, "dev", device], check=False)
            else:
                subprocess.run(["ip", "route", "del", subnet], check=False)
            logger.info(f"Removed existing route for {subnet}")
            time.sleep(0.5)  # Give system time to remove route
    except Exception as e:
        logger.error(f"Error removing route: {e}")

def cleanup_all_vpn_routes():
    """Clean up any existing VPN routes"""
    try:
        # Get all routes
        result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True)
        routes = result.stdout.split('\n')
        
        # Look for routes using any vpn interface
        for route in routes:
            if 'vpn' in route:
                # Extract the subnet from the route
                parts = route.split()
                if parts:
                    subnet = parts[0]
                    remove_route_if_exists(subnet)
        
        logger.info("Cleaned up existing VPN routes")
    except Exception as e:
        logger.error(f"Error cleaning up routes: {e}")


def is_local_address(addr):
    """Check if an address is local"""
    return addr in ('localhost', '127.0.0.1', '::1') or addr.startswith('192.168.') or addr.startswith('10.') or addr.startswith('172.')


def debug_network_state():
    """Print current network state for debugging"""
    try:
        logger.info("--- Network Debug Information ---")
        
        # Check routes
        logger.info("Routes:")
        subprocess.run(["ip", "route", "show"], check=True)
        
        # Check interfaces
        logger.info("\nInterfaces:")
        subprocess.run(["ip", "addr", "show"], check=True)
        
        # Check iptables
        logger.info("\nNAT Rules:")
        subprocess.run(["iptables", "-t", "nat", "-L", "-v", "-n"], check=True)
        
        # Check forwarding
        logger.info("\nIP Forwarding Status:")
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            logger.info(f"ip_forward = {f.read().strip()}")
        
        logger.info("--- End Debug Information ---")
    except Exception as e:
        logger.error(f"Error during network debugging: {e}")

def get_current_dns():
    """Get current DNS configuration including systemd-resolved"""
    dns_config = {
        'resolv_conf': [],
        'systemd_resolved': False,
        'resolved_stub': False
    }
    
    try:
        # Check if systemd-resolved is running
        resolved_check = subprocess.run(
            ["systemctl", "is-active", "systemd-resolved"],
            capture_output=True,
            text=True
        )
        dns_config['systemd_resolved'] = (resolved_check.stdout.strip() == 'active')
        
        # Read current resolv.conf
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_config['resolv_conf'].append(line.strip())
                    if '127.0.0.53' in line:
                        dns_config['resolved_stub'] = True
    except Exception as e:
        logger.error(f"Failed to read DNS configuration: {e}")
    
    return dns_config

def cleanup_interface(interface_name):
    """Cleanup any existing interface"""
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            subprocess.run(
                ["ip", "link", "delete", interface_name],
                check=True
            )
            time.sleep(1)
    except subprocess.CalledProcessError:
        pass

def find_available_interface():
    """Find an available TUN interface name"""
    for i in range(0, 100):
        interface_name = f"vpn{i}"
        result = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True
        )
        if result.returncode != 0:
            return interface_name
    raise RuntimeError("No available TUN interface names")

def get_default_interface():
    """Get the current default interface used for internet access"""
    try:
        # Get the default route info
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the output to get interface name
        # Output format: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
        route_parts = result.stdout.strip().split()
        if 'dev' in route_parts:
            idx = route_parts.index('dev')
            if idx + 1 < len(route_parts):
                return route_parts[idx + 1]
        
        raise RuntimeError("Could not find default interface")
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get default interface: {e}")

class VPNBase:
    def create_tun_interface(self):
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000
        
        tun = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack('16sH', self.interface_name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun, TUNSETIFF, ifr)
        return tun

class VPNServer(VPNBase):
    def __init__(self, listen_ip, listen_port, subnet, netmask):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.subnet = subnet
        self.netmask = netmask
        
        # Clean up any existing interfaces first
        for i in range(10):  # Check vpn0 through vpn9
            cleanup_interface(f"vpn{i}")
        
        time.sleep(1)  # Give system time to clean up
        
        self.interface_name = find_available_interface()
        logger.info(f"Using interface: {self.interface_name}")
        
        # Generate keypair
        self.private_key = nacl.public.PrivateKey.generate()
        self.public_key = self.private_key.public_key
        
        # Initialize client storage
        self.clients = {}
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((listen_ip, listen_port))
        
        # Setup TUN interface
        self.tun = self.create_tun_interface()
        self.configure_interface()
        
        logger.info(f"VPN Server started on {listen_ip}:{listen_port}")

    def get_default_interface():
        """Get the current default interface used for internet access"""
        try:
            # Get the default route info
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to get interface name
            # Output format: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
            route_parts = result.stdout.strip().split()
            if 'dev' in route_parts:
                idx = route_parts.index('dev')
                if idx + 1 < len(route_parts):
                    return route_parts[idx + 1]
            
            raise RuntimeError("Could not find default interface")
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get default interface: {e}")

    def configure_interface(self):
        try:
            # Get the internet-facing interface
            self.internet_iface = get_default_interface()
            logger.info(f"Detected internet-facing interface: {self.internet_iface}")
            
            # Configure TUN interface with IP
            subprocess.run([
                "ip", "addr", "add",
                f"{self.subnet}/{self.netmask}",
                "dev", self.interface_name
            ], check=True)
            
            subprocess.run([
                "ip", "link", "set", "up",
                "dev", self.interface_name
            ], check=True)
            
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            
            # Setup NAT rules
            iptables_rules = [
                # Clear existing rules that might conflict
                ["iptables", "-t", "nat", "-F"],
                ["iptables", "-F"],
                
                # Basic NAT for VPN clients
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", f"{self.subnet}/{self.netmask}",
                 "-o", self.internet_iface,
                 "-j", "MASQUERADE"],
                
                # Allow forwarding
                ["iptables", "-A", "FORWARD",
                 "-i", self.interface_name,
                 "-j", "ACCEPT"],
                
                ["iptables", "-A", "FORWARD",
                 "-o", self.interface_name,
                 "-j", "ACCEPT"]
            ]
            
            for rule in iptables_rules:
                subprocess.run(rule, check=True)
            
            logger.info(f"Server interface {self.interface_name} configured")
            debug_network_state()
            
        except Exception as e:
            logger.error(f"Failed to configure server interface: {e}")
            raise

    def cleanup(self):
        try:
            # Get the internet-facing interface
            internet_iface = get_default_interface()
            
            # Remove NAT rules
            try:
                subprocess.run([
                    "iptables", "-t", "nat", "-D", "POSTROUTING",
                    "-s", f"{self.subnet}/{self.netmask}",
                    "-o", f"{internet_iface}", "-j", "MASQUERADE"
                ])
            except subprocess.CalledProcessError:
                pass

            cleanup_interface(self.interface_name)
            os.close(self.tun)
            self.sock.close()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def handle_client_packet(self):
        while True:
            try:
                packet, addr = self.sock.recvfrom(MTU)
                
                if addr not in self.clients:
                    # New client connection
                    try:
                        logger.info(f"New connection from {addr}")
                        # First packet should be client public key
                        client_public_key = nacl.public.PublicKey(packet)
                        
                        # Assign IP
                        client_ip = self.get_available_ip()
                        
                        # Create response dictionary
                        response = {
                            'public_key': bytes(self.public_key).hex(),
                            'assigned_ip': client_ip
                        }
                        
                        # Send response as JSON
                        self.sock.sendto(json.dumps(response).encode('utf-8'), addr)
                        
                        # Create box
                        box = nacl.public.Box(self.private_key, client_public_key)
                        
                        self.clients[addr] = {
                            'box': box,
                            'ip': client_ip,
                            'last_seen': time.time()
                        }
                        logger.info(f"New client {addr} assigned IP: {client_ip}")
                        
                    except Exception as e:
                        logger.error(f"Error handling new client: {e}")
                        continue
                
                else:
                    try:
                        # Existing client
                        box = self.clients[addr]['box']
                        decrypted = box.decrypt(packet)
                        os.write(self.tun, decrypted)
                        self.clients[addr]['last_seen'] = time.time()
                    except Exception as e:
                        logger.error(f"Error handling client packet: {e}")
            
            except Exception as e:
                logger.error(f"Error in client packet handler: {e}")

    def monitor_clients(self):
        """Monitor client connections and clean up stale ones"""
        while True:
            try:
                current_time = time.time()
                to_remove = []
                
                for addr, client in self.clients.items():
                    if current_time - client.get('last_seen', 0) > 60:  # 60 seconds timeout
                        to_remove.append(addr)
                
                for addr in to_remove:
                    logger.info(f"Removing stale client {addr}")
                    del self.clients[addr]
                    
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in client monitor: {e}")


    def handle_tun_packet(self):
        while True:
            try:
                packet = os.read(self.tun, MTU)
                dst_ip = socket.inet_ntoa(packet[16:20])
                
                # Find client with matching IP
                for addr, client in self.clients.items():
                    if client['ip'] == dst_ip:
                        try:
                            encrypted = client['box'].encrypt(packet)
                            self.sock.sendto(encrypted, addr)
                        except Exception as e:
                            logger.error(f"Error sending to client {addr}: {e}")
                        break
            except Exception as e:
                logger.error(f"Error in TUN packet handler: {e}")

    def get_available_ip(self):
        used_ips = set(client['ip'] for client in self.clients.values())
        subnet_parts = self.subnet.split('.')
        for i in range(2, 254):
            ip = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.{i}"
            if ip not in used_ips:
                return ip
        raise Exception("No available IPs")

    def start(self):
        try:
            # Start the monitoring thread
            monitor_thread = Thread(target=self.monitor_clients, daemon=True)
            monitor_thread.start()
            
            # Start packet handling threads
            client_thread = Thread(target=self.handle_client_packet, daemon=True)
            tun_thread = Thread(target=self.handle_tun_packet, daemon=True)
            
            client_thread.start()
            tun_thread.start()
            
            logger.info("VPN server running. Press Ctrl+C to stop.")
            
            # Keep main thread alive and monitor thread status
            while True:
                if not client_thread.is_alive() or not tun_thread.is_alive():
                    logger.error("A handler thread has died! Restarting...")
                    if not client_thread.is_alive():
                        client_thread = Thread(target=self.handle_client_packet, daemon=True)
                        client_thread.start()
                    if not tun_thread.is_alive():
                        tun_thread = Thread(target=self.handle_tun_packet, daemon=True)
                        tun_thread.start()
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down VPN server...")
        except Exception as e:
            logger.error(f"Critical server error: {e}")
        finally:
            self.cleanup()

class VPNClient(VPNBase):
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_addr = (server_ip, server_port)
        self.interface_name = find_available_interface()
        
        # Cleanup any existing interface
        cleanup_interface(self.interface_name)
        
        # Generate keypair
        self.private_key = nacl.public.PrivateKey.generate()
        self.public_key = self.private_key.public_key
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Initialize server box as None until connection
        self.server_box = None
        
        # Setup TUN interface
        self.tun = self.create_tun_interface()
        
        logger.info(f"VPN Client started, connecting to {server_ip}:{server_port}")
        logger.info(f"Using interface: {self.interface_name}")

    def connect(self):
        try:
            logger.info("Sending public key to server...")
            # Send public key to server as raw bytes
            self.sock.sendto(bytes(self.public_key), self.server_addr)
            
            # Receive server's response
            logger.info("Waiting for server response...")
            data, _ = self.sock.recvfrom(MTU)
            
            # Parse JSON response
            try:
                response_data = json.loads(data.decode('utf-8'))
                server_public_key = nacl.public.PublicKey(
                    bytes.fromhex(response_data['public_key'])  # Convert hex string back to bytes
                )
                self.server_box = nacl.public.Box(self.private_key, server_public_key)
                assigned_ip = response_data['assigned_ip']
                
                logger.info(f"Got IP assignment: {assigned_ip}")
                self.configure_interface(assigned_ip)
                return True
                
            except Exception as e:
                logger.error(f"Failed to process server response: {e}")
                raise
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def backup_default_route(self):
        """Backup the current default route"""
        try:
            # Get current default route
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=True
            )
            self.original_route = result.stdout.strip()
            logger.info(f"Backed up original route: {self.original_route}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup default route: {e}")
            return False

    def delete_default_route(self):
        """Delete the current default route"""
        try:
            subprocess.run(
                ["ip", "route", "delete", "default"],
                check=True
            )
            logger.info("Deleted existing default route")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete default route: {e}")
            return False

    def restore_default_route(self):
        """Restore the original default route"""
        if hasattr(self, 'original_route') and self.original_route:
            try:
                # First, delete any existing default route
                subprocess.run(
                    ["ip", "route", "delete", "default"],
                    check=False  # Don't fail if no default route exists
                )

                # Restore original route
                subprocess.run(
                    ["ip", "route", "add"] + self.original_route.split(),
                    check=True
                )
                logger.info("Restored original default route")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restore default route: {e}")

    def configure_interface(self, assigned_ip):
        try:
            is_local = is_local_address(self.server_ip)
            logger.info(f"VPN Server is {'local' if is_local else 'remote'}")
            
            # Get network prefix from assigned IP
            network_prefix = '.'.join(assigned_ip.split('.')[:3]) + '.0'
            
            # Store original DNS configuration
            self.original_dns = get_current_dns()
            logger.info(f"Original DNS configuration: {self.original_dns}")
            
            # Configure the TUN interface
            subprocess.run([
                "ip", "addr", "add",
                f"{assigned_ip}/24",
                "dev", self.interface_name
            ], check=True)
            
            subprocess.run([
                "ip", "link", "set", "up",
                "dev", self.interface_name
            ], check=True)

            # Backup existing default route
            if not self.backup_default_route():
                raise RuntimeError("Failed to backup default route")

            if is_local:
                logger.info("Configuring routes for local VPN server")
                # For local testing, don't change default route
                # Add route for VPN network
                #subprocess.run([
                #    "ip", "route", "add",
                #    f"{network_prefix}/24",
                #    "dev", self.interface_name
                #], check=True)
            else:
                logger.info("Configuring routes for remote VPN server")
                # Delete existing default route
                if not self.delete_default_route():
                    raise RuntimeError("Failed to delete existing default route")

                # Add new default route through VPN
                subprocess.run([
                    "ip", "route", "add",
                    "default",
                    "via", assigned_ip,
                    "dev", self.interface_name
                ], check=True)

                # Add route to VPN server through original gateway
                original_gateway = self.original_route.split('via')[1].split()[0]
                original_interface = self.original_route.split('dev')[1].split()[0]
                subprocess.run([
                    "ip", "route", "add",
                    self.server_ip,
                    "via", original_gateway,
                    "dev", original_interface
                ], check=True)

            logger.info("Current network state after route changes:")
            debug_network_state()

            # Handle DNS configuration
            if self.original_dns['systemd_resolved']:
                if not is_local:
                    # Only modify DNS for remote VPN
                    self.configure_systemd_resolved()
            else:
                with open('/etc/resolv.conf', 'w') as f:
                    f.write("nameserver 8.8.8.8\n")
                    f.write("nameserver 8.8.4.4\n")

            time.sleep(2)
            self.test_connection()
            logger.info(f"Interface {self.interface_name} configured with IP: {assigned_ip}")
            
        except Exception as e:
            logger.error(f"Failed to configure interface: {e}")
            self.restore_default_route()
            raise

    def test_connection(self):
        """Test if the VPN connection is working"""
        try:
            is_local = is_local_address(self.server_ip)
            if is_local:
                logger.info("Testing local VPN connection...")
                # Get network prefix
                #network_prefix = '.'.join(self.server_ip.split('.')[:3]) + '.1'
                subprocess.run([
                    "ping", "-c", "1", "-W", "5",
                    self.server_ip
                ], check=True)
                logger.info("Local VPN connection working")
                return

            # Remote connection tests
            logger.info("Testing remote VPN connection...")
            subprocess.run([
                "ping", "-c", "1", "-W", "5",
                "8.8.8.8"
            ], check=True)
            logger.info("Remote VPN connection working")

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            raise RuntimeError("VPN connection not working properly")

    def configure_systemd_resolved(self):
        """Configure systemd-resolved to use VPN DNS"""
        try:
            # Create resolved.conf drop-in directory if it doesn't exist
            os.makedirs('/etc/systemd/resolved.conf.d', exist_ok=True)

            # Create VPN DNS configuration
            with open('/etc/systemd/resolved.conf.d/vpn.conf', 'w') as f:
                f.write("[Resolve]\n")
                f.write("DNS=8.8.8.8 8.8.4.4\n")
                f.write(f"Domains=~.\n")  # Send all queries through VPN DNS

            # Restart systemd-resolved to apply changes
            subprocess.run(["systemctl", "restart", "systemd-resolved"], check=True)

            logger.info("Configured systemd-resolved for VPN")

        except Exception as e:
            logger.error(f"Failed to configure systemd-resolved: {e}")
            raise

    def cleanup(self):
        logger.info("Starting VPN client cleanup...")
        try:
            # Restore DNS configuration
            if self.original_dns['systemd_resolved']:
                # Remove VPN DNS configuration
                try:
                    os.remove('/etc/systemd/resolved.conf.d/vpn.conf')
                    subprocess.run(["systemctl", "restart", "systemd-resolved"], check=True)
                except Exception as e:
                    logger.error(f"Error restoring systemd-resolved: {e}")
            else:
                # Restore original resolv.conf
                with open('/etc/resolv.conf', 'w') as f:
                    for line in self.original_dns['resolv_conf']:
                        f.write(f"{line}\n")

            # Restore original default route
            self.restore_default_route()

            # Clean up the interface
            cleanup_interface(self.interface_name)

            # Close file descriptors and sockets
            try:
                os.close(self.tun)
            except Exception as e:
                logger.error(f"Error closing TUN interface: {e}")

            try:
                self.sock.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        logger.info("VPN client cleanup completed")

    def handle_server_packet(self):
        while True:
            try:
                encrypted_packet, _ = self.sock.recvfrom(MTU)
                decrypted = self.server_box.decrypt(encrypted_packet)
                os.write(self.tun, decrypted)
            except Exception as e:
                logger.error(f"Error handling server packet: {e}")

    def handle_tun_packet(self):
        while True:
            try:
                packet = os.read(self.tun, MTU)
                encrypted = self.server_box.encrypt(packet)
                self.sock.sendto(encrypted, self.server_addr)
            except Exception as e:
                logger.error(f"Error sending to server: {e}")

    def start(self):
        try:
            if not self.connect():
                return
            
            server_thread = Thread(target=self.handle_server_packet, daemon=True)
            tun_thread = Thread(target=self.handle_tun_packet, daemon=True)
            
            server_thread.start()
            tun_thread.start()
            
            logger.info("VPN client running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down VPN client...")
        finally:
            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description="Simple VPN implementation")
    parser.add_argument("--mode", choices=['server', 'client'], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--subnet", default="10.0.0.0")
    parser.add_argument("--netmask", default="24")
    
    args = parser.parse_args()
    
    try:
        if args.mode == "server":
            server = VPNServer(args.host, args.port, args.subnet, args.netmask)
            server.start()
        else:
            client = VPNClient(args.host, args.port)
            client.start()
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()

