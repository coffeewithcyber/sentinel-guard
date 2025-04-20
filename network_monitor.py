import time
import threading
import logging
import socket
import struct
import os
import platform
import subprocess
import random
import ipaddress
from datetime import datetime
from app import db, app
from models import LogEntry, Alert

# Set up logging
logger = logging.getLogger(__name__)

# Try to import scapy, but don't fail if not available (will use fallback)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not available. Will use simulated packet capture.")
    SCAPY_AVAILABLE = False
    # Define dummy classes to prevent errors
    class DummyPacket(dict):
        pass
    IP = TCP = UDP = ICMP = ARP = DummyPacket

class NetworkMonitor:
    def __init__(self, threat_analyzer, alert_manager):
        self.threat_analyzer = threat_analyzer
        self.alert_manager = alert_manager
        self.monitoring = False
        self.thread = None
        self.app = app
        
        # Define private networks for IP classification
        self.private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]
        
        # Determine system type for platform-specific operations
        self.system_type = platform.system()  # 'Linux', 'Windows', or 'Darwin' (macOS)
        logger.info(f"Running on {self.system_type} platform")
    
    def start(self):
        """Start network monitoring in a separate thread"""
        if not self.monitoring:
            self.monitoring = True
            self.thread = threading.Thread(target=self._monitor_network)
            self.thread.daemon = True
            self.thread.start()
            logger.info("Network monitoring started")
    
    def stop(self):
        """Stop network monitoring"""
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Network monitoring stopped")
    
    def _monitor_network(self):
        """Monitor network traffic using Scapy if available, otherwise use simulation"""
        
        # Check if we should use real packet capture or simulation
        if SCAPY_AVAILABLE:
            try:
                logger.info("Starting real packet capture...")
                
                # Check if we have necessary permissions
                self._check_permissions()
                
                # Get the appropriate network interface
                interface = self._get_interface()
                logger.info(f"Capturing on interface: {interface}")
                
                # Start the packet capture
                sniff(prn=self._process_packet, 
                    store=0, 
                    iface=interface,
                    stop_filter=lambda p: not self.monitoring)
                    
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                logger.error("Falling back to simulated packet capture.")
                self._fallback_monitor_network()
        else:
            # If Scapy is not available, use simulated packet capture
            logger.info("Scapy not available. Using simulated packet capture.")
            self._fallback_monitor_network()
            
    def _check_permissions(self):
        """Check if we have necessary permissions for packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available")
            
        if self.system_type == "Linux" or self.system_type == "Darwin":
            # On Linux/macOS, check if we're running as root
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                logger.warning("Not running as root. Packet capture may be limited.")
        elif self.system_type == "Windows":
            # On Windows, check if WinPcap/Npcap is installed
            try:
                from scapy.arch.windows import get_windows_if_list
                get_windows_if_list()
            except Exception:
                logger.error("WinPcap/Npcap not properly installed on Windows.")
                raise RuntimeError("WinPcap/Npcap required for packet capture on Windows")
    
    def _get_interface(self):
        """Get the appropriate network interface for packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available")
            
        if self.system_type == "Linux":
            # Try to find the default interface on Linux
            try:
                # Use ip route to find default interface
                output = subprocess.check_output("ip route | grep default | awk '{print $5}'", 
                                              shell=True, 
                                              universal_newlines=True).strip()
                if output:
                    return output
            except Exception:
                pass
        
        # Use Scapy's built-in methods as fallback
        try:
            from scapy.config import conf
            return conf.iface  # Returns default interface
        except Exception:
            # If all else fails, return a default interface name
            if self.system_type == "Linux":
                return "eth0"
            elif self.system_type == "Windows":
                return "Ethernet"
            else:
                return "en0"  # macOS default
    
    def _generate_random_public_ip(self):
        """Generate a random public IP address"""
        while True:
            # Generate a random IP address
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            # Check if it's in a private range; if not, return it
            private = False
            for network in self.private_networks:
                if ipaddress.ip_address(ip) in network:
                    private = True
                    break
            
            if not private:
                return ip
    
    def _generate_random_mac(self):
        """Generate a random MAC address"""
        return ':'.join([f"{random.randint(0, 255):02x}" for _ in range(6)])
    
    def _fallback_monitor_network(self):
        """Fallback to simulated network monitoring if real capture fails"""
        # Define constants for simulation
        PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP"]
        COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        FLAGS = {
            "SYN": 2, 
            "SYN-ACK": 18, 
            "ACK": 16, 
            "PSH-ACK": 24, 
            "FIN": 1, 
            "RST": 4
        }
        
        logger.info("Using simulated packet capture as fallback...")
        
        while self.monitoring:
            # Simulate delays between packet captures
            time.sleep(random.uniform(0.1, 0.5))
            
            # Generate a simulated packet
            protocol = random.choice(PROTOCOLS)
            
            # Generate random private IP addresses for most traffic
            if random.random() < 0.8:  # 80% of traffic is private
                network = random.choice(self.private_networks)
                source_ip = str(random.choice(list(network.hosts())))
                dest_ip = str(random.choice(list(network.hosts())))
            else:  # 20% of traffic is public (potentially suspicious)
                source_ip = self._generate_random_public_ip()
                dest_ip = self._generate_random_public_ip()
            
            port = random.choice(COMMON_PORTS)
            data_size = random.randint(40, 1500)  # Typical packet size range
            
            # Create simulated packet
            simulated_packet = {
                'protocol': protocol,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'port': port,
                'data_size': data_size
            }
            
            # Add protocol-specific fields
            if protocol == "TCP":
                flag_name = random.choice(list(FLAGS.keys()))
                simulated_packet['flags'] = FLAGS[flag_name]
                simulated_packet['flag_name'] = flag_name
            elif protocol == "ICMP":
                simulated_packet['icmp_type'] = random.choice([0, 8])  # Echo reply or request
            elif protocol == "ARP":
                simulated_packet['hwsrc'] = self._generate_random_mac()
            
            # Process the simulated packet
            self._process_simulated_packet(simulated_packet)
    
    def _process_packet(self, packet):
        """Process a real captured packet from scapy"""
        try:
            # Use app context to ensure database operations work correctly
            with self.app.app_context():
                source_ip = None
                dest_ip = None
                protocol = None
                port = None
                data_size = len(packet)
                message = ""
                severity = "info"
                
                # Extract IP information if present
                if IP in packet:
                    source_ip = packet[IP].src
                    dest_ip = packet[IP].dst
                    
                    # Process TCP packets
                    if TCP in packet:
                        protocol = "TCP"
                        port = packet[TCP].dport
                        flags = packet[TCP].flags
                        
                        # Describe the packet based on TCP flags
                        if flags == 2:  # SYN
                            message = f"TCP SYN packet detected from {source_ip} to {dest_ip}:{port}"
                        elif flags == 18:  # SYN-ACK
                            message = f"TCP SYN-ACK packet detected from {source_ip} to {dest_ip}:{port}"
                        elif flags == 16:  # ACK
                            message = f"TCP ACK packet detected from {source_ip} to {dest_ip}:{port}"
                        elif flags == 24:  # PSH-ACK
                            message = f"TCP PSH-ACK packet detected from {source_ip} to {dest_ip}:{port}"
                        elif flags == 1:  # FIN
                            message = f"TCP FIN packet detected from {source_ip} to {dest_ip}:{port}"
                        elif flags == 4:  # RST
                            message = f"TCP RST packet detected from {source_ip} to {dest_ip}:{port}"
                        else:
                            message = f"TCP packet with flags {flags} detected from {source_ip} to {dest_ip}:{port}"
                    
                    # Process UDP packets
                    elif UDP in packet:
                        protocol = "UDP"
                        port = packet[UDP].dport
                        message = f"UDP packet detected from {source_ip} to {dest_ip}:{port}"
                    
                    # Process ICMP packets
                    elif ICMP in packet:
                        protocol = "ICMP"
                        icmp_type = packet[ICMP].type
                        
                        if icmp_type == 8:  # Echo Request
                            message = f"ICMP Echo Request (ping) from {source_ip} to {dest_ip}"
                        elif icmp_type == 0:  # Echo Reply
                            message = f"ICMP Echo Reply from {source_ip} to {dest_ip}"
                        else:
                            message = f"ICMP packet type {icmp_type} from {source_ip} to {dest_ip}"
                    
                    else:
                        protocol = f"IP({packet[IP].proto})"
                        message = f"IP packet detected from {source_ip} to {dest_ip}"
                
                # Process ARP packets
                elif ARP in packet:
                    protocol = "ARP"
                    source_ip = packet[ARP].psrc
                    dest_ip = packet[ARP].pdst
                    source_mac = packet[ARP].hwsrc
                    message = f"ARP packet: {source_ip} tells {dest_ip} about MAC {source_mac}"
                
                # Skip if we couldn't identify the packet
                if not source_ip or not dest_ip or not protocol:
                    return
                
                # Analyze for threats using the threat analyzer
                threat_result = self.threat_analyzer.analyze_packet(packet)
                if threat_result[0]:  # If a threat was detected
                    severity, threat_message, details = threat_result
                    message = threat_message
                
                # For ARP, check for spoofing
                if protocol == "ARP":
                    arp_threat = self.threat_analyzer.analyze_arp(packet)
                    if arp_threat[0]:
                        severity, threat_message, details = arp_threat
                        message = threat_message
                
                # Create log entry
                log_entry = LogEntry(
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    protocol=protocol,
                    port=port,
                    data_size=data_size,
                    message=message,
                    severity=severity,
                    timestamp=datetime.utcnow()
                )
                
                # If there's a security concern, create an alert
                if severity != "info":
                    details = f"Protocol: {protocol}, Source: {source_ip}, Destination: {dest_ip}:{port if port else ''}"
                    alert = Alert(
                        severity=severity,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        message=message,
                        details=details,
                        timestamp=datetime.utcnow()
                    )
                    
                    with db.session.begin_nested():
                        db.session.add(alert)
                    db.session.commit()
                    
                    # Send alert notification
                    self.alert_manager.send_alert(alert)
                
                # Save log entry
                with db.session.begin_nested():
                    db.session.add(log_entry)
                db.session.commit()
                
                # Emit the log entry to connected clients via SocketIO
                if hasattr(self.alert_manager, 'socketio'):
                    self.alert_manager.socketio.emit('new_log', log_entry.to_dict())
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_simulated_packet(self, packet):
        """Process a simulated packet (fallback method)"""
        try:
            # Use app context to ensure database operations work correctly
            with self.app.app_context():
                import random
                
                source_ip = packet['source_ip']
                dest_ip = packet['dest_ip']
                protocol = packet['protocol']
                port = packet.get('port')
                data_size = packet['data_size']
                message = ""
                severity = "info"
                
                # Generate appropriate message based on protocol
                if protocol == "TCP":
                    flag_name = packet['flag_name']
                    message = f"TCP {flag_name} packet detected from {source_ip} to {dest_ip}:{port}"
                    
                    # Occasionally generate suspicious TCP traffic
                    if random.random() < 0.05 and port in [22, 23, 3389]:  # SSH, Telnet, RDP
                        # Simulate potential brute force attack
                        if random.random() < 0.7:
                            severity = "medium"
                            message = f"Potential brute force attempt on {dest_ip}:{port} from {source_ip}"
                        else:
                            severity = "high"
                            message = f"Multiple failed login attempts on {dest_ip}:{port} from {source_ip}"
                    
                    # Simulate potential SYN flood attacks
                    elif flag_name == "SYN" and random.random() < 0.01:
                        severity = "critical"
                        message = f"Possible SYN flood attack detected from {source_ip} to {dest_ip}"
                
                elif protocol == "UDP":
                    message = f"UDP packet detected from {source_ip} to {dest_ip}:{port}"
                    
                    # Simulate DNS amplification attack occasionally
                    if port == 53 and random.random() < 0.02:
                        severity = "high"
                        message = f"Potential DNS amplification attack from {source_ip} to {dest_ip}"
                
                elif protocol == "ICMP":
                    icmp_type = packet['icmp_type']
                    if icmp_type == 8:  # Echo Request
                        message = f"ICMP Echo Request (ping) from {source_ip} to {dest_ip}"
                        
                        # Simulate ping sweep/scan occasionally
                        if random.random() < 0.05:
                            severity = "medium"
                            message = f"Potential ping sweep detected from {source_ip}"
                    else:
                        message = f"ICMP Echo Reply from {source_ip} to {dest_ip}"
                
                elif protocol == "ARP":
                    message = f"ARP packet: {source_ip} tells {dest_ip} about MAC {packet['hwsrc']}"
                    
                    # Simulate potential ARP spoofing
                    if random.random() < 0.02:
                        severity = "high"
                        message = f"Potential ARP spoofing detected from {source_ip}"
                
                # Create log entry
                log_entry = LogEntry(
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    protocol=protocol,
                    port=port,
                    data_size=data_size,
                    message=message,
                    severity=severity,
                    timestamp=datetime.utcnow()
                )
                
                # If there's a security concern, create an alert
                if severity != "info":
                    details = f"Protocol: {protocol}, Source: {source_ip}, Destination: {dest_ip}:{port if port else ''}"
                    alert = Alert(
                        severity=severity,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        message=message,
                        details=details,
                        timestamp=datetime.utcnow()
                    )
                    
                    with db.session.begin_nested():
                        db.session.add(alert)
                    db.session.commit()
                    
                    # Send alert notification
                    self.alert_manager.send_alert(alert)
                
                # Save log entry
                with db.session.begin_nested():
                    db.session.add(log_entry)
                db.session.commit()
                
                # This will emit the log entry to connected clients via SocketIO
                try:
                    if hasattr(self.alert_manager, 'socketio'):
                        log_dict = log_entry.to_dict()
                        self.alert_manager.socketio.emit('new_log', log_dict)
                        logger.debug(f"Emitted log: {log_dict}")
                except Exception as e:
                    logger.error(f"Error emitting log via SocketIO: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing simulated packet: {e}")
