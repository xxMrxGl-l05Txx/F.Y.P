# check_alert_methods.py
import logging
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.alerts.alert_system import AlertManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create alert manager
alert_manager = AlertManager()

# Check which alert methods are enabled
print(f"Active alert methods ({len(alert_manager.alert_methods)}):")
for i, method in enumerate(alert_manager.alert_methods):
    print(f"  {i+1}. {method.__class__.__name__}")

# Print configuration
print("\nAlert Manager Configuration:")
for key, value in alert_manager.config.items():
    print(f"  {key}: {value}")