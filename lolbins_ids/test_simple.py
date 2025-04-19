import sys
import os
import logging
from datetime import datetime
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Create a test alert
test_alert = {
    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    'rule_name': "PowerShell Encoded Command",
    'description': "PowerShell executing encoded commands",
    'severity': 4,
    'process_name': "powershell.exe",
    'command_line': "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
    'pid': 1234,
    'username': "test_user"
}

# Test direct notification
try:
    from src.notification.providers.system_tray_simple import SystemTrayProvider
    
    print("Testing simple system tray notification...")
    provider = SystemTrayProvider({"enabled": True})
    result = provider.send_notification(test_alert)
    print(f"Notification sent: {result}")
    
    # Wait to see the notification
    print("Waiting for notification to appear... (5 seconds)")
    time.sleep(5)
    
except Exception as e:
    logging.error(f"Error testing notification: {str(e)}")

print("Test complete")