import sys
import os
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import components
from notification.notification_orchestrator import NotificationOrchestrator
from notification.providers.system_tray import SystemTrayProvider
from notification.providers.email_provider import EmailProvider

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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

# Test individual providers
print("Testing System Tray provider...")
tray_config = {"enabled": True, "min_severity": 1}
system_tray = SystemTrayProvider(tray_config)
system_tray.send_notification(test_alert)

# Uncomment to test email provider
# print("Testing Email provider...")
# email_config = {
#     "enabled": True, 
#     "min_severity": 3,
#     "smtp_server": "your-smtp-server",
#     "smtp_port": 587,
#     "smtp_username": "your-username",
#     "smtp_password": "your-password",
#     "from_address": "alerts@example.com",
#     "recipients": ["your-email@example.com"]
# }
# email_provider = EmailProvider(email_config)
# email_provider.send_notification(test_alert)

# Test orchestrator
print("Testing Notification Orchestrator...")
orchestrator = NotificationOrchestrator()
orchestrator.process_alert(test_alert)

print("Test complete")