Python VPN 
Quick VPN implementation in Python using UDP and public/private keys.
Run it
Server:
sudo pip3 install pynacl
sudo python3 vpn.py --mode server --host 0.0.0.0 --port 5000
Client:
sudo python3 vpn.py --mode client --host server_ip --port 5000

What it does
Creates TUN interfaces
Handles NAT and routing
Encrypts traffic with NaCl
Manages DNS stuff
Shows packet logs

Requirements

Linux
Python 3
root access
pynacl package

Python VPN - Local Testing Version
Same VPN but for testing locally using Unix sockets. 
Run it
Terminal 1:
sudo python3 vpn.py --mode server --host localhost
Terminal 2:
sudo python3 vpn.py --mode client --host localhost


Creates two TUN interfaces (vpn0, vpn1)
Uses Unix sockets instead of UDP
Still encrypts everything
Shows packet details
