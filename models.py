from datetime import datetime
from app import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_notifications = db.Column(db.Boolean, default=True)
    email_recipients = db.Column(db.String(255), default="")
    alert_threshold_critical = db.Column(db.Integer, default=90)
    alert_threshold_high = db.Column(db.Integer, default=70)
    alert_threshold_medium = db.Column(db.Integer, default=50)
    alert_threshold_low = db.Column(db.Integer, default=30)
    smtp_server = db.Column(db.String(128), default="")
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(128), default="")
    smtp_password = db.Column(db.String(128), default="")
    monitoring_enabled = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Settings {self.id}>'


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    source_ip = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<Alert {self.id} - {self.severity}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'acknowledged': self.acknowledged,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None
        }


class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    port = db.Column(db.Integer, nullable=True)
    data_size = db.Column(db.Integer, nullable=True)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="info")  # critical, high, medium, low, info
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<LogEntry {self.id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'port': self.port,
            'data_size': self.data_size,
            'message': self.message,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    format = db.Column(db.String(10), default="pdf")  # pdf, csv, json, txt
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Report {self.id} - {self.title}>'
