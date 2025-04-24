# Enhanced app.py for the dashboard
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO
import os
import sys
import json
import logging
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rules.enhanced_rule_engine import EnhancedRuleEngine
from alerts.alert_system import AlertManager
from utils.performance_monitor import PerformanceMonitor
from notification.notification_orchestrator import NotificationOrchestrator
from src.database.connection import DatabaseConnection
import pymongo
from src.analysis.threat_analyzer import ThreatAnalyzer

@app.route('/analysis')
def analysis_dashboard():
    analyzer = ThreatAnalyzer()
    
    # Get data for dashboard
    attack_patterns = analyzer.get_attack_patterns(days=7)
    high_risk_users = analyzer.get_high_risk_users(days=7)
    lolbin_usage = analyzer.get_common_lolbin_usage(days=7)
    mitre_summary = analyzer.get_mitre_attack_summary(days=7)
    
    return render_template(
        'analysis.html',
        attack_patterns=attack_patterns,
        high_risk_users=high_risk_users,
        lolbin_usage=lolbin_usage,
        mitre_summary=mitre_summary
    )

def get_recent_alerts(limit=10):
    """Get recent alerts for dashboard display"""
    return list(db.alerts.find(
        {}, 
        sort=[("timestamp", pymongo.DESCENDING)],
        limit=limit
    ))
    
    
def get_alerts_by_severity():
    """Get count of alerts by severity level"""
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}  # Sort by severity
    ]
    return list(db.alerts.aggregate(pipeline))

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
@app.route('/api/alerts')
def get_alerts():
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                data = json.load(f)
                if "alerts" in data:
                    return jsonify(data["alerts"])
                return jsonify(data)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error loading alerts: {str(e)}")
        return jsonify([])

@app.route('/api/rules')
def get_rules():
    try:
        rules_data = [{"name": rule.name, 
                        "lolbin": rule.lolbin, 
                        "pattern": rule.pattern.pattern, 
                        "severity": rule.severity,
                        "status": "active"} 
                      for rule in rule_engine.rules]
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

# Run the app
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)