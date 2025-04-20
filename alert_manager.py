import os
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from models import Settings, Alert
from app import db

# Set up logging
logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, socketio):
        self.socketio = socketio
        self.email_lock = threading.Lock()
        self.last_email_sent = {}  # {alert_type: timestamp}
        
    def send_alert(self, alert):
        """Send an alert through appropriate channels"""
        try:
            # Always emit to socketio for real-time updates
            self._send_realtime_alert(alert)
            
            # Send email for high severity alerts if enabled
            if alert.severity in ['critical', 'high']:
                self._send_email_alert(alert)
                
            logger.info(f"Alert sent: {alert.severity} - {alert.message}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def _send_realtime_alert(self, alert):
        """Send real-time alert through SocketIO"""
        try:
            alert_data = {
                'id': alert.id,
                'severity': alert.severity,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat() if alert.timestamp else datetime.utcnow().isoformat()
            }
            
            self.socketio.emit('new_alert', alert_data)
            
        except Exception as e:
            logger.error(f"Error sending real-time alert: {e}")
    
    def _send_email_alert(self, alert):
        """Send email alert"""
        try:
            # Get settings
            settings = db.session.query(Settings).first()
            
            # Check if email notifications are enabled
            if not settings or not settings.email_notifications:
                return
            
            # Check rate limiting to prevent email flooding
            with self.email_lock:
                now = datetime.utcnow()
                alert_type = f"{alert.severity}:{alert.source_ip}"
                
                # Only send one email per alert type per 15 minutes
                if alert_type in self.last_email_sent:
                    time_diff = (now - self.last_email_sent[alert_type]).total_seconds()
                    if time_diff < 900:  # 15 minutes in seconds
                        logger.info(f"Rate limiting email for {alert_type}")
                        return
                
                self.last_email_sent[alert_type] = now
            
            # Check if email settings are configured
            if not settings.smtp_server or not settings.email_recipients:
                logger.warning("Email settings not configured, skipping email alert")
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = settings.smtp_username or 'sentinel-guard@localhost'
            msg['To'] = settings.email_recipients
            msg['Subject'] = f"Sentinel-Guard {alert.severity.upper()} Alert"
            
            # Email body
            body = f"""
            <html>
            <body>
                <h2>Sentinel-Guard Security Alert</h2>
                <p><strong>Severity:</strong> {alert.severity.upper()}</p>
                <p><strong>Time:</strong> {alert.timestamp}</p>
                <p><strong>Source IP:</strong> {alert.source_ip}</p>
                <p><strong>Destination IP:</strong> {alert.destination_ip}</p>
                <p><strong>Alert Message:</strong> {alert.message}</p>
                <p><strong>Details:</strong> {alert.details}</p>
                <hr>
                <p>This is an automated message from your Sentinel-Guard security system.</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Connect to SMTP server and send email
            try:
                server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
                server.ehlo()
                server.starttls()
                
                # Login if credentials provided
                if settings.smtp_username and settings.smtp_password:
                    server.login(settings.smtp_username, settings.smtp_password)
                
                server.send_message(msg)
                server.close()
                
                logger.info(f"Email alert sent for {alert.severity} alert to {settings.email_recipients}")
                
            except Exception as e:
                logger.error(f"Failed to send email alert: {e}")
                
        except Exception as e:
            logger.error(f"Error preparing email alert: {e}")
