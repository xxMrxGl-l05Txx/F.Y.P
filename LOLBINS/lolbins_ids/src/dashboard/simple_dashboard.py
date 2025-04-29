# Create a file called simple_dashboard.py
from flask import Flask, render_template, jsonify
import json
import os
import logging

app = Flask(__name__)

ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')

@app.route('/')
def home():
    return render_template('simple_dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
            return jsonify(alerts)
        else:
            return jsonify([])
    except Exception as e:
        logging.error(f"Error loading alerts: {str(e)}")
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)