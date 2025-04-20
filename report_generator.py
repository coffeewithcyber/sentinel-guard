import os
import csv
import json
import logging
from datetime import datetime, timedelta
import io
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from models import Alert, LogEntry, Report
from app import db

# Set up logging
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.report_dir = 'reports'
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_report(self, report_type, start_date, end_date, format_type='pdf'):
        """Generate a report based on the specified parameters"""
        try:
            # Make sure end_date is the end of the day
            end_date = end_date.replace(hour=23, minute=59, second=59)
            
            # Get data for the report
            if report_type == 'alerts':
                data = self._get_alert_data(start_date, end_date)
                title = "Security Alerts Report"
                headers = ["ID", "Timestamp", "Severity", "Source IP", "Destination IP", "Message"]
            elif report_type == 'traffic':
                data = self._get_traffic_data(start_date, end_date)
                title = "Network Traffic Report"
                headers = ["ID", "Timestamp", "Protocol", "Source IP", "Destination IP", "Port", "Size", "Severity"]
            elif report_type == 'summary':
                data, headers = self._get_summary_data(start_date, end_date)
                title = "Security Summary Report"
            else:
                return None
            
            # Create filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{report_type}_{timestamp}.{format_type}"
            filepath = os.path.join(self.report_dir, filename)
            
            # Generate report in the requested format
            if format_type == 'pdf':
                self._generate_pdf(filepath, title, headers, data, start_date, end_date)
            elif format_type == 'csv':
                self._generate_csv(filepath, headers, data)
            elif format_type == 'json':
                self._generate_json(filepath, headers, data)
            elif format_type == 'txt':
                self._generate_txt(filepath, title, headers, data, start_date, end_date)
            
            logger.info(f"Generated {report_type} report in {format_type} format: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None
    
    def download_report(self, report):
        """Send the report file for download"""
        try:
            return send_file(report.file_path, 
                            as_attachment=True,
                            download_name=os.path.basename(report.file_path),
                            mimetype=self._get_mimetype(report.format))
        except Exception as e:
            logger.error(f"Error downloading report: {e}")
            return None
    
    def _get_mimetype(self, format_type):
        """Get the correct MIME type for the report format"""
        mime_types = {
            'pdf': 'application/pdf',
            'csv': 'text/csv',
            'json': 'application/json',
            'txt': 'text/plain'
        }
        return mime_types.get(format_type, 'application/octet-stream')
    
    def _get_alert_data(self, start_date, end_date):
        """Get alert data for the report"""
        alerts = Alert.query.filter(
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).order_by(Alert.timestamp.desc()).all()
        
        data = []
        for alert in alerts:
            data.append([
                alert.id,
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                alert.severity.upper(),
                alert.source_ip,
                alert.destination_ip,
                alert.message
            ])
        
        return data
    
    def _get_traffic_data(self, start_date, end_date):
        """Get traffic data for the report"""
        logs = LogEntry.query.filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).order_by(LogEntry.timestamp.desc()).all()
        
        data = []
        for log in logs:
            data.append([
                log.id,
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.protocol,
                log.source_ip,
                log.destination_ip,
                log.port,
                log.data_size,
                log.severity.upper()
            ])
        
        return data
    
    def _get_summary_data(self, start_date, end_date):
        """Get summary data for the report"""
        # Alert counts by severity
        critical = Alert.query.filter(Alert.severity == 'critical', 
                                    Alert.timestamp >= start_date,
                                    Alert.timestamp <= end_date).count()
        high = Alert.query.filter(Alert.severity == 'high', 
                                Alert.timestamp >= start_date,
                                Alert.timestamp <= end_date).count()
        medium = Alert.query.filter(Alert.severity == 'medium', 
                                    Alert.timestamp >= start_date,
                                    Alert.timestamp <= end_date).count()
        low = Alert.query.filter(Alert.severity == 'low', 
                                Alert.timestamp >= start_date,
                                Alert.timestamp <= end_date).count()
        info = Alert.query.filter(Alert.severity == 'info', 
                                Alert.timestamp >= start_date,
                                Alert.timestamp <= end_date).count()
        
        # Total traffic count
        traffic_count = LogEntry.query.filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()
        
        # Top source IPs
        top_sources = db.session.query(
            LogEntry.source_ip, db.func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).group_by(LogEntry.source_ip).order_by(db.text('count DESC')).limit(5).all()
        
        # Top destination IPs
        top_destinations = db.session.query(
            LogEntry.destination_ip, db.func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).group_by(LogEntry.destination_ip).order_by(db.text('count DESC')).limit(5).all()
        
        # Top protocols
        top_protocols = db.session.query(
            LogEntry.protocol, db.func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date,
            LogEntry.protocol != None
        ).group_by(LogEntry.protocol).order_by(db.text('count DESC')).limit(5).all()
        
        # Compile the data
        data = [
            ["Alert Statistics", ""],
            ["Critical Alerts", critical],
            ["High Alerts", high],
            ["Medium Alerts", medium],
            ["Low Alerts", low],
            ["Informational", info],
            ["Total Alerts", critical + high + medium + low + info],
            ["", ""],
            ["Traffic Statistics", ""],
            ["Total Traffic Records", traffic_count],
            ["", ""],
            ["Top Source IPs", "Count"],
        ]
        
        for src_ip, count in top_sources:
            data.append([src_ip, count])
        
        data.append(["", ""])
        data.append(["Top Destination IPs", "Count"])
        
        for dest_ip, count in top_destinations:
            data.append([dest_ip, count])
        
        data.append(["", ""])
        data.append(["Top Protocols", "Count"])
        
        for protocol, count in top_protocols:
            data.append([protocol, count])
        
        # Latest critical and high alerts
        latest_alerts = Alert.query.filter(
            Alert.severity.in_(['critical', 'high']),
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).order_by(Alert.timestamp.desc()).limit(10).all()
        
        if latest_alerts:
            data.append(["", ""])
            data.append(["Latest Critical/High Alerts", ""])
            data.append(["Timestamp", "Severity", "Source IP", "Message"])
            
            for alert in latest_alerts:
                data.append([
                    alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    alert.severity.upper(),
                    alert.source_ip,
                    alert.message
                ])
        
        # Headers for the summary report are custom
        headers = []
        
        return data, headers
    
    def _generate_pdf(self, filepath, title, headers, data, start_date, end_date):
        """Generate a PDF report"""
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        elements = []
        
        # Add styles
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        subtitle_style = styles['Heading2']
        normal_style = styles['Normal']
        
        # Add title
        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 12))
        
        # Add date range
        date_range = f"Report Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        elements.append(Paragraph(date_range, subtitle_style))
        elements.append(Spacer(1, 12))
        
        # Add generation timestamp
        generated = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elements.append(Paragraph(generated, normal_style))
        elements.append(Spacer(1, 24))
        
        # Add watermark text
        elements.append(Paragraph("Sentinel-Guard", styles['Italic']))
        elements.append(Spacer(1, 12))
        
        # Create table for report data
        if headers:  # Regular report with headers
            table_data = [headers] + data
            t = Table(table_data)
            
            # Add table styles
            style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ])
            
            # Add color coding for severity if it's an alert report
            if 'Severity' in headers:
                severity_col = headers.index('Severity')
                for i, row in enumerate(data, 1):
                    if row[severity_col] == 'CRITICAL':
                        style.add('BACKGROUND', (severity_col, i), (severity_col, i), colors.darkred)
                        style.add('TEXTCOLOR', (severity_col, i), (severity_col, i), colors.white)
                    elif row[severity_col] == 'HIGH':
                        style.add('BACKGROUND', (severity_col, i), (severity_col, i), colors.red)
                        style.add('TEXTCOLOR', (severity_col, i), (severity_col, i), colors.white)
                    elif row[severity_col] == 'MEDIUM':
                        style.add('BACKGROUND', (severity_col, i), (severity_col, i), colors.orange)
                    elif row[severity_col] == 'LOW':
                        style.add('BACKGROUND', (severity_col, i), (severity_col, i), colors.blue)
                        style.add('TEXTCOLOR', (severity_col, i), (severity_col, i), colors.white)
                    elif row[severity_col] == 'INFO':
                        style.add('BACKGROUND', (severity_col, i), (severity_col, i), colors.lightblue)
            
            t.setStyle(style)
            elements.append(t)
            
        else:  # Summary report with custom format
            # Process the summary data which has a different format
            for i, row in enumerate(data):
                if len(row) >= 2:
                    if row[0] and row[0].endswith("Statistics") or row[0] == "Latest Critical/High Alerts":
                        # Section headers
                        elements.append(Spacer(1, 12))
                        elements.append(Paragraph(row[0], subtitle_style))
                        elements.append(Spacer(1, 6))
                    elif row[0] == "Timestamp" and len(row) >= 4:
                        # Alert table header
                        t_data = [row]
                        j = i + 1
                        while j < len(data) and len(data[j]) >= 4:
                            t_data.append(data[j])
                            j += 1
                        
                        t = Table(t_data)
                        style = TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ])
                        
                        # Color coding for severity
                        for k, alert_row in enumerate(t_data[1:], 1):
                            if alert_row[1] == 'CRITICAL':
                                style.add('BACKGROUND', (1, k), (1, k), colors.darkred)
                                style.add('TEXTCOLOR', (1, k), (1, k), colors.white)
                            elif alert_row[1] == 'HIGH':
                                style.add('BACKGROUND', (1, k), (1, k), colors.red)
                                style.add('TEXTCOLOR', (1, k), (1, k), colors.white)
                        
                        t.setStyle(style)
                        elements.append(t)
                        
                    elif row[0] == "Top Source IPs" or row[0] == "Top Destination IPs" or row[0] == "Top Protocols":
                        # Start of a top-X section
                        elements.append(Spacer(1, 6))
                        elements.append(Paragraph(row[0], normal_style))
                        
                        # Collect the items for this section
                        t_data = [row]
                        j = i + 1
                        while j < len(data) and data[j][0] and data[j][0] != "":
                            t_data.append(data[j])
                            j += 1
                        
                        t = Table(t_data)
                        t.setStyle(TableStyle([
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ]))
                        elements.append(t)
                        
                    elif row[0] and row[1] != "" and row[0] != "":
                        # Regular key-value pair
                        value_text = f"{row[0]}: {row[1]}"
                        elements.append(Paragraph(value_text, normal_style))
        
        # Build the PDF
        doc.build(elements)
    
    def _generate_csv(self, filepath, headers, data):
        """Generate a CSV report"""
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if headers:
                writer.writerow(headers)
            writer.writerows(data)
    
    def _generate_json(self, filepath, headers, data):
        """Generate a JSON report"""
        json_data = []
        
        if headers:
            for row in data:
                item = {}
                for i, header in enumerate(headers):
                    item[header] = row[i] if i < len(row) else ""
                json_data.append(item)
        else:
            # Summary report - just use the raw data
            json_data = data
        
        with open(filepath, 'w') as jsonfile:
            json.dump(json_data, jsonfile, indent=4)
    
    def _generate_txt(self, filepath, title, headers, data, start_date, end_date):
        """Generate a plain text report"""
        with open(filepath, 'w') as txtfile:
            # Write title and dates
            txtfile.write(f"{title}\n")
            txtfile.write("="*len(title) + "\n\n")
            txtfile.write(f"Report Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n")
            txtfile.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            txtfile.write("SENTINEL-GUARD SECURITY REPORT\n\n")
            
            if headers:
                # Write headers
                header_row = "\t".join(headers)
                txtfile.write(header_row + "\n")
                txtfile.write("-"*len(header_row) + "\n")
                
                # Write data rows
                for row in data:
                    txtfile.write("\t".join([str(item) for item in row]) + "\n")
            else:
                # Summary report
                for row in data:
                    if len(row) >= 2:
                        if row[0] and row[0].endswith("Statistics") or row[0] == "Latest Critical/High Alerts":
                            txtfile.write(f"\n{row[0]}\n")
                            txtfile.write("-"*len(row[0]) + "\n")
                        elif row[0] == "Timestamp" and len(row) >= 4:
                            # Alert table header
                            txtfile.write(f"\n{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}\n")
                            txtfile.write("-"*50 + "\n")
                        elif row[0] == "Top Source IPs" or row[0] == "Top Destination IPs" or row[0] == "Top Protocols":
                            txtfile.write(f"\n{row[0]}\t{row[1]}\n")
                            txtfile.write("-"*30 + "\n")
                        elif row[0] and row[1] != "" and row[0] != "":
                            txtfile.write(f"{row[0]}:\t{row[1]}\n")
                        elif row[0] == "":
                            txtfile.write("\n")
