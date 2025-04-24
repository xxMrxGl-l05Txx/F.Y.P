# test_alert.py
from src.notification.notification_orchestrator import NotificationOrchestrator

orchestrator = NotificationOrchestrator()
test_alert = {
    'timestamp': '2025-04-24 12:00:00',
    'rule_name': 'Test Alert',
    'description': 'This is a test alert from the notification system',
    'severity': 4,
    'process_name': 'test.exe',
    'command_line': 'test.exe --test-notification',
    'pid': 1234,
    'username': 'test_user'
}
orchestrator.process_alert(test_alert)