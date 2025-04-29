# Enhanced app.py for the dashboard
import io
import csv
from datetime import datetime
from flask import make_response, request
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO
from flask import request
import os
import sys
import json
import logging
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.mitre_mappings import MITRE_ATTACK_MAPPINGS
from rules.enhanced_rule_engine import EnhancedRuleEngine
from alerts.alert_system import AlertManager
from utils.performance_monitor import PerformanceMonitor
from notification.notification_orchestrator import NotificationOrchestrator
# from src.database.connection import DatabaseConnection
import pymongo
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.threat_analyzer import ThreatAnalyzer

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dashboard')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'lolbins_ids_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
alert_manager = AlertManager()
rule_engine = EnhancedRuleEngine()
performance_monitor = PerformanceMonitor()

# Initialize notification orchestrator
notification_orchestrator = NotificationOrchestrator()

# Path to alerts file
ALERTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'alerts.json')
if not os.path.exists(ALERTS_FILE):
    ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')

@app.route('/analysis')
def analysis_dashboard():
    analyzer = ThreatAnalyzer()
    
    # Get data for dashboard
    attack_patterns = analyzer.get_attack_patterns(days=7)
    high_risk_users = analyzer.get_high_risk_users(days=7)
    lolbin_usage = analyzer.get_common_lolbin_usage(days=7)
    mitre_summary = analyzer.get_mitre_attack_summary(days=7)
    
    # Database connection setup
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client.lolbins_ids
    
    # Define the aggregation pipeline
    pipeline = [
        {"$match": {"timestamp": {"$gte": datetime.now() - timedelta(days=7)}}},
        {"$sort": {"severity": -1}}
    ]
    
    alerts_data = list(db.alerts.aggregate(pipeline))
    
    return render_template('analysis.html', 
                          attack_patterns=attack_patterns,
                          high_risk_users=high_risk_users,
                          lolbin_usage=lolbin_usage,
                          mitre_summary=mitre_summary,
                          alerts=alerts_data)

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dashboard')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lolbins_ids_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
alert_manager = AlertManager()
rule_engine = EnhancedRuleEngine()
performance_monitor = PerformanceMonitor()

# Initialize notification orchestrator
notification_orchestrator = NotificationOrchestrator()

# Path to alerts file
ALERTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'alerts.json')
if not os.path.exists(ALERTS_FILE):
    ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/rules')
def rules():
    return render_template('rule_management.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/whitelist')
def whitelist():
    return render_template('whitelist.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
def logout():
    # This would normally contain logout logic
    return redirect(url_for('dashboard'))

# API routes for data
# API routes for data
@app.route('/api/alerts')
def get_alerts():
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                data = json.load(f)
                
                # Enrich alerts with MITRE ATT&CK information
                alerts = data.get("alerts", data)
                for alert in alerts:
                    rule_name = alert.get("rule_name", "")
                    if rule_name in MITRE_ATTACK_MAPPINGS:
                        alert["mitre_attack"] = MITRE_ATTACK_MAPPINGS[rule_name]
                        # Add mitigation URL
                        technique_id = MITRE_ATTACK_MAPPINGS[rule_name]["technique_id"]
                        # Remove subtype if present (e.g., T1059.001 -> T1059)
                        base_technique = technique_id.split('.')[0] if '.' in technique_id else technique_id
                        alert["mitre_attack"]["mitigation_url"] = f"https://attack.mitre.org/techniques/{base_technique}/mitigations/"
                    else:
                        alert["mitre_attack"] = None
                
                if "alerts" in data:
                    return jsonify(data["alerts"])
                return jsonify(alerts)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error loading alerts: {str(e)}")
        return jsonify([])

@app.route('/api/rules')
def get_rules():
    try:
        rules_data = []
        for rule in rule_engine.rules:
            rule_info = {
                "name": rule.name, 
                "lolbin": rule.lolbin, 
                "pattern": rule.pattern.pattern, 
                "severity": rule.severity,
                "status": "active"
            }
            
            # Add MITRE ATT&CK information
            if rule.name in MITRE_ATTACK_MAPPINGS:
                rule_info["mitre_attack"] = MITRE_ATTACK_MAPPINGS[rule.name]
                # Add mitigation URL
                technique_id = MITRE_ATTACK_MAPPINGS[rule.name]["technique_id"]
                # Remove subtype if present (e.g., T1059.001 -> T1059)
                base_technique = technique_id.split('.')[0] if '.' in technique_id else technique_id
                rule_info["mitre_attack"]["mitigation_url"] = f"https://attack.mitre.org/techniques/{base_technique}/mitigations/"
            else:
                rule_info["mitre_attack"] = None
                
            rules_data.append(rule_info)
            
        return jsonify(rules_data)
    except Exception as e:
        logging.error(f"Error loading rules: {str(e)}")
        return jsonify([])
    
@app.route('/api/performance')
def get_performance():
    try:
        return jsonify(performance_monitor.get_performance_summary())
    except Exception as e:
        logging.error(f"Error getting performance metrics: {str(e)}")
        return jsonify({})

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

# Handle real-time notifications
@socketio.on('subscribe_notifications')
def handle_subscribe_notifications(data):
    logger.info(f'Client subscribed to notifications: {data}')

# Function to emit notification to all connected clients
def emit_notification(alert):
    socketio.emit('notification', alert)
    logger.info(f'Notification emitted: {alert["rule_name"]}')


# ADD YOUR ERROR HANDLER HERE
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 error: {request.path}")
    # Return a friendly error page with links to valid pages
    return render_template('error.html', error=str(e)), 404

@app.route('/api/export', methods=['GET'])
def export_data():
    try:
        # Get export parameters
        export_type = request.args.get('type', 'alerts')  # alerts, reports, etc.
        format = request.args.get('format', 'csv')        # csv, json, etc.
        time_range = request.args.get('range', 'all')     # all, day, week, month
        severity = request.args.get('severity', 'all')    # all, 1, 2, 3, 4, 5
        
        # Get data based on export type
        data = []
        
        if export_type == 'alerts':
            try:
                # Try to get from MongoDB first
                mongo_provider = MongoDataProvider()
                
                # Apply filters based on parameters
                if time_range != 'all':
                    days = 1 if time_range == 'day' else 7 if time_range == 'week' else 30
                    data = mongo_provider.get_filtered_alerts(days=days, severity=severity)
                else:
                    data = mongo_provider.get_recent_alerts(limit=1000)
                    
                    # Filter by severity if requested
                    if severity != 'all':
                        data = [alert for alert in data if str(alert.get('severity', 0)) == severity]
                
            except Exception as mongo_error:
                logging.warning(f"MongoDB export failed, using file: {str(mongo_error)}")
                
                # Fall back to file-based alerts
                if os.path.exists(ALERTS_FILE):
                    with open(ALERTS_FILE, 'r') as f:
                        file_data = json.load(f)
                        if isinstance(file_data, list):
                            data = file_data
                        elif isinstance(file_data, dict) and 'alerts' in file_data:
                            data = file_data['alerts']
        
        # Format data based on requested format
        if format.lower() == 'json':
            response = make_response(jsonify(data))
            response.headers['Content-Disposition'] = f'attachment; filename=lolbins_export_{export_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            response.headers['Content-Type'] = 'application/json'
            return response
            
        elif format.lower() == 'csv':
            # Create CSV content
            csv_content = io.StringIO()
            
            if data and len(data) > 0:
                # Get fieldnames from the first item
                fieldnames = data[0].keys()
                
                writer = csv.DictWriter(csv_content, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            
            response = make_response(csv_content.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename=lolbins_export_{export_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            response.headers['Content-Type'] = 'text/csv'
            return response
            
        else:
            return jsonify({"error": "Unsupported export format"}), 400
            
    except Exception as e:
        logging.error(f"Export error: {str(e)}")
        return jsonify({"error": f"Export failed: {str(e)}"}), 500

# Run the app
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)