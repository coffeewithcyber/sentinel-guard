import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy base
class Base(DeclarativeBase):
    pass

# Initialize Flask app and extensions
db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "sentinel-guard-default-secret")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///sentinel.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Set up login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User, Settings, Alert, Report, LogEntry
from network_monitor import NetworkMonitor
from threat_analyzer import ThreatAnalyzer
from alert_manager import AlertManager
from report_generator import ReportGenerator

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Initialize database tables
with app.app_context():
    db.create_all()
    # Check if we have settings, if not create default
    if not db.session.query(Settings).first():
        default_settings = Settings(
            email_notifications=True,
            email_recipients="admin@example.com",
            alert_threshold_critical=90,
            alert_threshold_high=70,
            alert_threshold_medium=50,
            alert_threshold_low=30,
            smtp_server="smtp.example.com",
            smtp_port=587,
            smtp_username="",
            smtp_password="",
            monitoring_enabled=True
        )
        db.session.add(default_settings)
        db.session.commit()

# Initialize components
analyzer = ThreatAnalyzer()
alert_manager = AlertManager(socketio)
report_generator = ReportGenerator()

# Start network monitor if configured to run
network_monitor = None

def start_monitoring():
    global network_monitor
    settings = db.session.query(Settings).first()
    if settings and settings.monitoring_enabled and network_monitor is None:
        network_monitor = NetworkMonitor(analyzer, alert_manager)
        network_monitor.start()
        logger.info("Network monitoring started")
    elif network_monitor:
        logger.info("Network monitoring already running")

def stop_monitoring():
    global network_monitor
    if network_monitor:
        network_monitor.stop()
        network_monitor = None
        logger.info("Network monitoring stopped")

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        user_exists = User.query.filter((User.username == username) | 
                                        (User.email == email)).first()
        
        if user_exists:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get the latest 100 log entries
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(100).all()
    # Get alert summary
    alert_summary = {
        'critical': Alert.query.filter_by(severity='critical').count(),
        'high': Alert.query.filter_by(severity='high').count(),
        'medium': Alert.query.filter_by(severity='medium').count(),
        'low': Alert.query.filter_by(severity='low').count(),
        'info': Alert.query.filter_by(severity='info').count(),
    }
    # Get latest alerts
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                           logs=logs, 
                           alert_summary=alert_summary,
                           alerts=alerts)

@app.route('/reports')
@login_required
def reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('reports.html', reports=reports)

@app.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    report_type = request.form.get('report_type')
    start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
    end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
    format_type = request.form.get('format', 'pdf')
    
    # Generate a report
    report_path = report_generator.generate_report(report_type, start_date, end_date, format_type)
    
    # Create a report entry
    new_report = Report(
        title=f"{report_type.capitalize()} Report ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})",
        description=f"Generated {report_type} report covering {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
        file_path=report_path,
        format=format_type,
        created_by=current_user.id
    )
    
    db.session.add(new_report)
    db.session.commit()
    
    flash(f'Report generated successfully in {format_type.upper()} format', 'success')
    return redirect(url_for('reports'))

@app.route('/report/<int:report_id>/download')
@login_required
def download_report(report_id):
    report = Report.query.get_or_404(report_id)
    return report_generator.download_report(report)

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    settings = db.session.query(Settings).first()
    
    if request.method == 'POST':
        settings.email_notifications = 'email_notifications' in request.form
        settings.email_recipients = request.form.get('email_recipients')
        settings.alert_threshold_critical = int(request.form.get('alert_threshold_critical'))
        settings.alert_threshold_high = int(request.form.get('alert_threshold_high'))
        settings.alert_threshold_medium = int(request.form.get('alert_threshold_medium'))
        settings.alert_threshold_low = int(request.form.get('alert_threshold_low'))
        settings.smtp_server = request.form.get('smtp_server')
        settings.smtp_port = int(request.form.get('smtp_port'))
        settings.smtp_username = request.form.get('smtp_username')
        
        # Only update password if provided
        new_smtp_password = request.form.get('smtp_password')
        if new_smtp_password:
            settings.smtp_password = new_smtp_password
            
        monitoring_enabled = 'monitoring_enabled' in request.form
        if monitoring_enabled and not settings.monitoring_enabled:
            settings.monitoring_enabled = True
            db.session.commit()
            start_monitoring()
        elif not monitoring_enabled and settings.monitoring_enabled:
            settings.monitoring_enabled = False
            db.session.commit()
            stop_monitoring()
        else:
            db.session.commit()
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', settings=settings)

# API Routes
@app.route('/api/alerts')
@login_required
def api_alerts():
    limit = request.args.get('limit', 100, type=int)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([alert.to_dict() for alert in alerts])

@app.route('/api/logs')
@login_required
def api_logs():
    limit = request.args.get('limit', 100, type=int)
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])

@app.route('/api/alert_summary')
@login_required
def api_alert_summary():
    # Count both alerts and log entries for a complete picture
    alerts_summary = {
        'critical': Alert.query.filter_by(severity='critical').count(),
        'high': Alert.query.filter_by(severity='high').count(),
        'medium': Alert.query.filter_by(severity='medium').count(),
        'low': Alert.query.filter_by(severity='low').count(),
        'info': Alert.query.filter_by(severity='info').count(),
    }
    
    logs_summary = {
        'critical': LogEntry.query.filter_by(severity='critical').count(),
        'high': LogEntry.query.filter_by(severity='high').count(),
        'medium': LogEntry.query.filter_by(severity='medium').count(),
        'low': LogEntry.query.filter_by(severity='low').count(),
        'info': LogEntry.query.filter_by(severity='info').count(),
    }
    
    # Combine both counts
    summary = {
        'critical': alerts_summary['critical'] + logs_summary['critical'],
        'high': alerts_summary['high'] + logs_summary['high'],
        'medium': alerts_summary['medium'] + logs_summary['medium'],
        'low': alerts_summary['low'] + logs_summary['low'],
        'info': alerts_summary['info'] + logs_summary['info'],
    }
    
    return jsonify(summary)

# SocketIO events
@socketio.on('connect')
def handle_connect():
    logger.debug('Client connected to SocketIO')

@socketio.on('disconnect')
def handle_disconnect():
    logger.debug('Client disconnected from SocketIO')

# Start monitoring if enabled
with app.app_context():
    settings = db.session.query(Settings).first()
    if settings and settings.monitoring_enabled:
        start_monitoring()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
