# Enhanced app.py for the dashboard
from flask import Flask, render_template, jsonify, request
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


# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alerts.alert_system import AlertManager
from rules.enhanced_rule_engine import EnhancedRuleEngine
from utils.performance_monitor import PerformanceMonitor

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lolbins_ids_secret_key'
socketio = SocketIO(app)

# Initialize components
alert_manager = AlertManager()
rule_engine = EnhancedRuleEngine()
performance_monitor = PerformanceMonitor()

# Path to alerts file
ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lolbins_alerts.json')

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/rules')
def rules():
    return render_template('rule_management.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

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
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# Run the app
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)