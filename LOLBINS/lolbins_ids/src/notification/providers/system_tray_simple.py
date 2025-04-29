import logging
import os
from datetime import datetime

class SystemTrayProvider:
    """Simplified provider for Windows system tray notifications"""
    
    def __init__(self, config):
        self.config = config
        # Try to import Windows-specific modules
        try:
            from win10toast import ToastNotifier
            self.toast = ToastNotifier()
            self.available = True
        except ImportError:
            logging.error("win10toast not found. Install with: pip install win10toast")
            self.available = False
    
    def send_notification(self, alert):
        """Send a notification through this provider"""
        if not self.available:
            return False
            
        try:
            severity = alert.get('severity', 1)
            rule_name = alert.get('rule_name', 'Unknown Rule')
            process = alert.get('process_name', 'Unknown Process')
            description = alert.get('description', 'No description')
            
            # Format title based on severity
            if severity >= 5:
                title_prefix = "CRITICAL ALERT"
            elif severity >= 4:
                title_prefix = "HIGH SEVERITY ALERT"
            elif severity >= 3:
                title_prefix = "MEDIUM ALERT"
            else:
                title_prefix = "ALERT"
            
            title = f"{title_prefix}: {rule_name}"
            
            # Format message
            message = f"Process: {process}\n{description}"
            
            # Add correlation info if present
            if alert.get('correlation', {}).get('is_correlated', False):
                chain_info = alert['correlation']
                if chain_info.get('attack_chain_complete', False):
                    message += f"\n\nATTACK CHAIN DETECTED: {chain_info.get('rule_name', 'Unknown Attack Chain')}"
            
            # Show the notification
            self.toast.show_toast(
                title=title,
                msg=message,
                icon_path=None,  # None for default app icon
                duration=5,  # Show for 5 seconds
                threaded=True
            )
            return True
            
        except Exception as e:
            logging.error(f"Error showing toast notification: {str(e)}")
            return False