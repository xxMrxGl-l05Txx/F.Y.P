# # app.py
# from flask import Flask, render_template, jsonify, request
# from flask_socketio import SocketIO
# import json
# import os
# import sys
# import logging
# from datetime import datetime, timedelta
# import pandas as pd
# import plotly
# import plotly.express as px
# import plotly.graph_objects as go
# import threading
# from functools import lru_cache

# # Add parent directory to path for imports
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# from alerts.alert_system import AlertManager
# from utils.performance_monitor import PerformanceMonitor

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )

# # Initialize Flask app
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'lolbins_ids_secret_key'
# socketio = SocketIO(app)

# # Initialize alert manager and performance monitor
# alert_manager = AlertManager()
# performance_monitor = PerformanceMonitor()

# # Path to alerts JSON file
# ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')

# # Route for the dashboard homepage
# @app.route('/')
# def home():
#     return render_template('dashboard.html')

# # API route to get all alerts
# @app.route('/api/alerts')
# def get_alerts():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
#         else:
#             alerts = []
#         return jsonify(alerts)
#     except Exception as e:
#         logging.error(f"Error loading alerts: {str(e)}")
#         return jsonify([])

# # API route to get recent alerts (last 24 hours)
# @app.route('/api/alerts/recent')
# def get_recent_alerts():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
            
#             # Filter for alerts in the last 24 hours
#             cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d")
#             recent_alerts = [alert for alert in alerts if alert.get('timestamp', '').startswith(cutoff)]
#             return jsonify(recent_alerts)
#         else:
#             return jsonify([])
#     except Exception as e:
#         logging.error(f"Error loading recent alerts: {str(e)}")
#         return jsonify([])

# # API route to get alerts by severity
# @app.route('/api/alerts/severity')
# def get_alerts_by_severity():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
            
#             # Count alerts by severity
#             severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
#             for alert in alerts:
#                 severity = alert.get('severity', 0)
#                 if severity in severity_counts:
#                     severity_counts[severity] += 1
            
#             return jsonify(severity_counts)
#         else:
#             return jsonify({1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
#     except Exception as e:
#         logging.error(f"Error analyzing alerts by severity: {str(e)}")
#         return jsonify({1: 0, 2: 0, 3: 0, 4: 0, 5: 0})

# # API route to get alerts by LOLBin type
# @app.route('/api/alerts/lolbins')
# def get_alerts_by_lolbin():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
            
#             # Count alerts by LOLBin type
#             lolbin_counts = {}
#             for alert in alerts:
#                 process_name = alert.get('process_name', 'unknown')
#                 if process_name in lolbin_counts:
#                     lolbin_counts[process_name] += 1
#                 else:
#                     lolbin_counts[process_name] = 1
            
#             return jsonify(lolbin_counts)
#         else:
#             return jsonify({})
#     except Exception as e:
#         logging.error(f"Error analyzing alerts by LOLBin: {str(e)}")
#         return jsonify({})

# # API route to get performance metrics
# @app.route('/api/performance')
# def get_performance():
#     try:
#         metrics = performance_monitor.get_current_metrics()
#         return jsonify(metrics)
#     except Exception as e:
#         logging.error(f"Error getting performance metrics: {str(e)}")
#         return jsonify({})

# # API route to get charts data
# @app.route('/api/charts/alerts_over_time')
# def get_alerts_over_time_chart():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
            
#             # Convert to DataFrame for easier manipulation
#             df = pd.DataFrame(alerts)
            
#             if df.empty:
#                 return jsonify({})
            
#             # Extract date from timestamp
#             df['date'] = df['timestamp'].str.split(' ').str[0]
            
#             # Count alerts by date
#             date_counts = df['date'].value_counts().reset_index()
#             date_counts.columns = ['date', 'count']
#             date_counts = date_counts.sort_values('date')
            
#             # Create plotly figure
#             fig = px.line(date_counts, x='date', y='count', title='Alerts Over Time')
            
#             return jsonify({
#                 'chart': json.loads(plotly.io.to_json(fig))
#             })
#         else:
#             return jsonify({})
#     except Exception as e:
#         logging.error(f"Error creating alerts over time chart: {str(e)}")
#         return jsonify({})

# # API route to get severity distribution chart
# @app.route('/api/charts/severity_distribution')
# def get_severity_chart():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 alerts = json.load(f)
            
#             # Count alerts by severity
#             severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
#             for alert in alerts:
#                 severity = alert.get('severity', 0)
#                 if severity in severity_counts:
#                     severity_counts[severity] += 1
            
#             # Convert to format for plotting
#             df = pd.DataFrame({
#                 'Severity': list(severity_counts.keys()),
#                 'Count': list(severity_counts.values())
#             })
            
#             # Create plotly figure
#             fig = px.bar(
#                 df, 
#                 x='Severity', 
#                 y='Count', 
#                 title='Alert Severity Distribution',
#                 color='Severity',
#                 color_continuous_scale=['blue', 'green', 'yellow', 'orange', 'red']
#             )
            
#             return jsonify({
#                 'chart': json.loads(plotly.io.to_json(fig))
#             })
#         else:
#             return jsonify({})
#     except Exception as e:
#         logging.error(f"Error creating severity distribution chart: {str(e)}")
#         return jsonify({})

# # Socket event for real-time updates
# @socketio.on('connect')
# def handle_connect():
#     logging.info('Client connected')

# @socketio.on('disconnect')
# def handle_disconnect():
#     logging.info('Client disconnected')

# # Main function to run the app
# def main():
#     logging.info("Starting LOLBins IDS Dashboard")
#     app.run(debug=False, host='0.0.0.0', port=5000)  # Set debug=False for better performance


# if __name__ == '__main__':
#     main()
    
# @app.route('/api/alerts')
# def get_alerts():
#     return jsonify(get_cached_alerts())

# # Add this function to your app.py file

# @app.route('/api/alerts/summary')
# def get_alerts_summary():
#     try:
#         from data_provider import DataProvider
#         provider = DataProvider()
#         summary = provider.get_alerts_summary()
#         return jsonify(summary)
#     except Exception as e:
#         logging.error(f"Error getting alerts summary: {str(e)}")
#         return jsonify({
#             "total_alerts": 0,
#             "high_severity_alerts": 0,
#             "recent_alerts": 0,
#             "most_common_lolbin": "Error",
#             "most_triggered_rule": "Error"
#         })

# @lru_cache(maxsize=32)
# def get_cached_alerts():
#     try:
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 return json.load(f)
#         return []
#     except Exception as e:
#         logging.error(f"Error loading alerts: {str(e)}")
#         return []
    
# @app.route('/api/charts/alerts_over_time')
# def get_alerts_over_time_chart():
#     try:
#         alerts = get_cached_alerts()
#         if not alerts:
#             return jsonify({})
            
#         # Simplified chart generation
#         dates = {}
#         for alert in alerts:
#             date = alert.get('timestamp', '').split(' ')[0]
#             dates[date] = dates.get(date, 0) + 1
        
#         # Convert to lists for plotting
#         x_values = list(dates.keys())
#         y_values = list(dates.values())
        
#         # Create a simpler figure
#         fig = {
#             'data': [{
#                 'x': x_values,
#                 'y': y_values,
#                 'type': 'scatter',
#                 'mode': 'lines+markers'
#             }],
#             'layout': {
#                 'title': 'Alerts Over Time',
#                 'xaxis': {'title': 'Date'},
#                 'yaxis': {'title': 'Count'}
#             }
#         }
        
#         return jsonify({'chart': fig})
#     except Exception as e:
#         logging.error(f"Error creating alerts over time chart: {str(e)}")
#         return jsonify({})

# app.py
from flask import Flask, render_template, jsonify, request
import json
import os
import logging
import sys
from datetime import datetime, timedelta
from functools import lru_cache

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'lolbins_ids_secret_key'

# Path to alerts JSON file
ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')

# Cache for expensive operations
@lru_cache(maxsize=32)
def get_cached_alerts():
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                data = json.load(f)
                # Check if the data is wrapped in an "alerts" object
                if isinstance(data, dict) and "alerts" in data:
                    return data["alerts"]
                return data
        return []
    except Exception as e:
        logging.error(f"Error loading alerts: {str(e)}")
        return []

# Route for the dashboard homepage
@app.route('/')
def home():
    return render_template('dashboard.html')

# API route to get all alerts
@app.route('/api/alerts')
def get_alerts():
    try:
        return jsonify(get_cached_alerts())
    except Exception as e:
        logging.error(f"Error loading alerts: {str(e)}")
        return jsonify([])

# API route to get recent alerts (last 24 hours)
@app.route('/api/alerts/recent')
def get_recent_alerts():
    try:
        alerts = get_cached_alerts()
        
        # Filter for alerts in the last 24 hours
        now = datetime.now()
        cutoff = now - timedelta(hours=24)
        recent_alerts = []
        
        for alert in alerts:
            try:
                alert_time = datetime.strptime(alert.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                if alert_time >= cutoff:
                    recent_alerts.append(alert)
            except ValueError:
                # Skip alerts with invalid timestamp
                continue
                
        return jsonify(recent_alerts)
    except Exception as e:
        logging.error(f"Error loading recent alerts: {str(e)}")
        return jsonify([])

# API route to get alerts by severity
@app.route('/api/alerts/severity')
def get_alerts_by_severity():
    try:
        alerts = get_cached_alerts()
        
        # Count alerts by severity
        severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for alert in alerts:
            severity = alert.get('severity', 0)
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return jsonify(severity_counts)
    except Exception as e:
        logging.error(f"Error analyzing alerts by severity: {str(e)}")
        return jsonify({1: 0, 2: 0, 3: 0, 4: 0, 5: 0})

# API route to get alerts by LOLBin type
@app.route('/api/alerts/lolbins')
def get_alerts_by_lolbin():
    try:
        alerts = get_cached_alerts()
        
        # Count alerts by LOLBin type
        lolbin_counts = {}
        for alert in alerts:
            process_name = alert.get('process_name', 'unknown')
            if process_name in lolbin_counts:
                lolbin_counts[process_name] += 1
            else:
                lolbin_counts[process_name] = 1
        
        return jsonify(lolbin_counts)
    except Exception as e:
        logging.error(f"Error analyzing alerts by LOLBin: {str(e)}")
        return jsonify({})

# API route to get summary data for the dashboard
@app.route('/api/alerts/summary')
def get_alerts_summary():
    try:
        alerts = get_cached_alerts()
        
        # Count high severity alerts (4-5)
        high_severity = sum(1 for alert in alerts if alert.get('severity', 0) >= 4)
        
        # Count recent alerts (last 24 hours)
        now = datetime.now()
        cutoff = now - timedelta(hours=24)
        recent = 0
        
        for alert in alerts:
            try:
                alert_time = datetime.strptime(alert.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                if alert_time >= cutoff:
                    recent += 1
            except ValueError:
                # Skip alerts with invalid timestamp
                continue
                
        # Get most common LOLBin
        lolbin_counts = {}
        for alert in alerts:
            process_name = alert.get('process_name', 'unknown')
            lolbin_counts[process_name] = lolbin_counts.get(process_name, 0) + 1
            
        most_common_lolbin = max(lolbin_counts.items(), key=lambda x: x[1])[0] if lolbin_counts else "None"
        
        # Get most triggered rule
        rule_counts = {}
        for alert in alerts:
            rule_name = alert.get('rule_name', 'unknown')
            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
            
        most_triggered_rule = max(rule_counts.items(), key=lambda x: x[1])[0] if rule_counts else "None"
        
        return jsonify({
            "total_alerts": len(alerts),
            "high_severity_alerts": high_severity,
            "recent_alerts": recent,
            "most_common_lolbin": most_common_lolbin,
            "most_triggered_rule": most_triggered_rule
        })
    except Exception as e:
        logging.error(f"Error generating alerts summary: {str(e)}")
        return jsonify({
            "total_alerts": 0,
            "high_severity_alerts": 0,
            "recent_alerts": 0,
            "most_common_lolbin": "Error",
            "most_triggered_rule": "Error"
        })

# Main function to run the app
def main():
    logging.info("Starting LOLBins IDS Dashboard")
    # Use this for better performance in production
    app.run(debug=False, host='0.0.0.0', port=5000)
    
    # Alternatively, if you install waitress, you can use:
    # from waitress import serve
    # serve(app, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()