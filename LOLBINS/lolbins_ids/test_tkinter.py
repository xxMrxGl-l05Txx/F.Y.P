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
    'description': "PowerShell executing encoded commands that could indicate an attempt to hide malicious activity. Encoded PowerShell commands are commonly used by attackers to bypass security controls and execute malware.",
    'severity': 4,
    'process_name': "powershell.exe",
    'command_line': "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
    'pid': 1234,
    'username': "DESKTOP\\Administrator"
}

# Test direct notification
try:
    from src.notification.providers.tkinter_notifier import TkinterNotifierProvider
    
    print("Testing Tkinter notification...")
    provider = TkinterNotifierProvider({"enabled": True})
    result = provider.send_notification(test_alert)
    print(f"Notification queued: {result}")
    
    # Keep program running while notification is displayed
    print("Notification dialog should appear. This window will close in 40 seconds.")
    time.sleep(40)
    
except Exception as e:
    logging.error(f"Error testing notification: {str(e)}")

print("Test complete")