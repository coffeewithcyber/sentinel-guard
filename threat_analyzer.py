import logging
import re
import socket
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Set up logging
logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self):
        # Initialize counters for tracking connection attempts, etc.
        self.syn_counters = defaultdict(Counter)
        self.connection_attempts = defaultdict(Counter)
        self.icmp_counters = defaultdict(Counter)
        self.port_scan_threshold = 5  # Number of different ports to qualify as a port scan
        self.last_cleanup = datetime.utcnow()
        self.cleanup_interval = timedelta(minutes=5)
        
        # Known bad IPs (you might want to load these from a file or database)
        self.blacklisted_ips = set()
        
        # Common attack patterns
        self.attack_patterns = [
            (re.compile(r'<script.*?>.*?</script>', re.I), 'XSS Attack Pattern'),
            (re.compile(r'(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*FROM', re.I), 'SQL Injection Pattern'),
            (re.compile(r'\.\./', re.I), 'Directory Traversal Pattern'),
        ]
        
        # Known malicious ports and services
        self.suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            4444: "Metasploit default",
            5900: "VNC",
            8080: "HTTP Alternate",
        }
        
        # ARP cache to detect spoofing
        self.arp_cache = {}  # {ip: mac}

    def _cleanup_old_data(self):
        """Clean up old data in counters to prevent memory bloat"""
        current_time = datetime.utcnow()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self.syn_counters.clear()
            self.connection_attempts.clear()
            self.icmp_counters.clear()
            self.last_cleanup = current_time
            logger.debug("Cleaned up threat analyzer counters")

    def analyze_packet(self, packet):
        """
        Analyze a simulated packet for potential threats
        Returns: (severity, message, details) or (None, None, None) if no threat
        """
        self._cleanup_old_data()
        
        # Since we're dealing with simulated packets now, we'll return None 
        # and let the NetworkMonitor handle the threat detection in its _process_packet method
        # This helps avoid duplicating code and makes the system more maintainable
        return None, None, None

    def analyze_arp(self, packet):
        """
        Analyze ARP packets for spoofing attacks
        Returns: (severity, message, details) or (None, None, None) if no threat
        """
        # For simulated packets, the ARP analysis is handled in the NetworkMonitor
        return None, None, None
        
    def get_random_threat(self):
        """Generate a random threat for simulation purposes"""
        severities = ["low", "medium", "high", "critical"]
        weights = [0.5, 0.3, 0.15, 0.05]  # More weighted toward lower severities
        
        severity = random.choices(severities, weights=weights, k=1)[0]
        
        threat_types = {
            "low": [
                ("Port scan detected", "Multiple ports scanned from same source"),
                ("Unusual protocol activity", "Non-standard protocol usage detected"),
                ("Multiple failed logins", "Repeated login failures from same source")
            ],
            "medium": [
                ("Suspicious traffic pattern", "Potential data exfiltration detected"),
                ("Brute force attempt", "Multiple authentication attempts on restricted service"),
                ("DNS tunneling suspected", "Unusual DNS query patterns detected")
            ],
            "high": [
                ("Possible DDoS attack", "High volume of traffic targeting specific service"),
                ("SQL injection attempt", "Malicious SQL patterns detected in HTTP request"),
                ("Known exploit attempt", "Signature matches known vulnerability exploit")
            ],
            "critical": [
                ("Active intrusion detected", "Malicious command execution observed"),
                ("Ransomware activity", "File encryption signatures detected"),
                ("Data breach in progress", "Unauthorized database extraction detected")
            ]
        }
        
        message, details = random.choice(threat_types[severity])
        return severity, message, details
