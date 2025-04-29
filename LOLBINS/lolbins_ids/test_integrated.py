# lolbins_ids/test_integrated.py
import sys
import os
import logging
from datetime import datetime
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import components
from rules.enhanced_rule_engine import EnhancedRuleEngine
from notification.notification_orchestrator import NotificationOrchestrator

def test_detection_to_notification():
    """Test the complete flow from detection to notification"""
    # Initialize components
    rule_engine = EnhancedRuleEngine()
    orchestrator = NotificationOrchestrator()
    
    print("Running integrated test...")
    print("1. Setting up simulated LOLBin execution")
    
    # Simulate a suspicious process
    test_process = {
        'name': 'powershell.exe',
        'cmdline': ['powershell.exe', '-e', 'ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA='],  # Using -e shorthand which matches the rule pattern
        'pid': 1234,
        'username': 'DESKTOP\\Administrator'
    }
    
    print("2. Analyzing process with rule engine")
    # Analyze process with rule engine
    alerts = rule_engine.analyze_process(test_process)
    
    if not alerts:
        print("No alerts generated. Something may be wrong with the rule engine.")
        return
    
    print(f"3. Generated {len(alerts)} alerts")
    for idx, alert in enumerate(alerts, 1):
        print(f"   Alert {idx}: {alert['rule_name']} (Severity: {alert['severity']})")
    
    print("4. Sending alerts to notification system")
    # Send alerts to notification system
    for alert in alerts:
        orchestrator.process_alert(alert)
    
    print("Test completed. You should see notification dialogs appearing.")
    print("Keeping process alive for 30 seconds to allow notifications to display...")
    time.sleep(30)

if __name__ == "__main__":
    test_detection_to_notification()