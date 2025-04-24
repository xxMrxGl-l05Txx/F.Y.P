# notification_dashboard_connector.py
# A connector script to bridge the notification system and dashboard

import os
import sys
import json
import socket
import logging
import threading
import time
import queue
from datetime import datetime
import socketio

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notification.notification_orchestrator import NotificationOrchestrator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('notification_connector')

class NotificationDashboardConnector:
    """
    Connects the notification system to the dashboard using Socket.IO
    to provide real-time alert notifications in the web interface.
    """
    
    def __init__(self, dashboard_url='http://localhost:5000', alert_file=None):
        """
        Initialize the connector.
        
        Args:
            dashboard_url (str): URL of the dashboard for Socket.IO connection
            alert_file (str): Path to the alerts JSON file
        """
        self.dashboard_url = dashboard_url
        self.sio = socketio.Client()
        self.connected = False
        self.alert_queue = queue.Queue()
        self.notification_orchestrator = None
        
        # Path to alerts file
        if alert_file:
            self.alert_file = alert_file
        else:
            # Try to find the alert file
            self.alert_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dashboard', 'alerts.json')
            if not os.path.exists(self.alert_file):
                self.alert_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.json')
        
        # Setup Socket.IO event handlers
        self._setup_socketio_handlers()
        
        # Start processing threads
        self.running = True
        self.connect_thread = threading.Thread(target=self._connection_manager)
        self.connect_thread.daemon = True
        self.connect_thread.start()
        
        self.alert_thread = threading.Thread(target=self._process_alert_queue)
        self.alert_thread.daemon = True
        self.alert_thread.start()
        
        logger.info(f"Notification Dashboard Connector initialized with dashboard URL: {dashboard_url}")
    
    def _setup_socketio_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.sio.event
        def connect():
            logger.info("Connected to dashboard Socket.IO server")
            self.connected = True
        
        @self.sio.event
        def disconnect():
            logger.info("Disconnected from dashboard Socket.IO server")
            self.connected = False
        
        @self.sio.event
        def connect_error(data):
            logger.error(f"Connection error: {data}")
            self.connected = False
    
    def _connection_manager(self):
        """Manages the Socket.IO connection to the dashboard"""
        while self.running:
            if not self.connected:
                try:
                    logger.info(f"Attempting to connect to dashboard at {self.dashboard_url}")
                    self.sio.connect(self.dashboard_url)
                except Exception as e:
                    logger.error(f"Failed to connect to dashboard: {str(e)}")
                    time.sleep(5)  # Retry after 5 seconds
            
            # Check connection status every 30 seconds
            time.sleep(30)
    
    def _process_alert_queue(self):
        """Process alerts from the queue and send them to the dashboard"""
        while self.running:
            try:
                # Get alert from queue with timeout
                try:
                    alert = self.alert_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Send alert to dashboard if connected
                if self.connected:
                    try:
                        self.sio.emit('notification', alert)
                        logger.info(f"Sent alert to dashboard: {alert.get('rule_name', 'Unknown alert')}")
                    except Exception as e:
                        logger.error(f"Error sending alert to dashboard: {str(e)}")
                        # Put the alert back in the queue
                        self.alert_queue.put(alert)
                else:
                    # If not connected, put the alert back in the queue
                    logger.warning("Not connected to dashboard, re-queuing alert")
                    self.alert_queue.put(alert)
                    time.sleep(1)  # Avoid tight loop
                
                # Mark as done if processed
                if self.connected:
                    self.alert_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing alert queue: {str(e)}")
                time.sleep(1)  # Avoid tight loop on error
    
    def initialize_orchestrator(self, config_file=None):
        """Initialize the notification orchestrator with a custom alert handler"""
        try:
            # Create notification orchestrator with our queue-based handler
            self.notification_orchestrator = NotificationOrchestrator(config_file)
            
            # Store the original process_alert method
            original_process_alert = self.notification_orchestrator.process_alert
            
            # Create a wrapper method that also adds alerts to our dashboard queue
            def process_alert_wrapper(alert):
                # Call the original method
                result = original_process_alert(alert)
                
                # Add to our dashboard queue
                self.alert_queue.put(alert)
                
                # Also save to the alerts file
                self._save_alert(alert)
                
                return result
            
            # Replace the original method with our wrapper
            self.notification_orchestrator.process_alert = process_alert_wrapper
            
            logger.info("Notification orchestrator initialized with dashboard connector")
            return self.notification_orchestrator
        
        except Exception as e:
            logger.error(f"Error initializing notification orchestrator: {str(e)}")
            return None
    
    def _save_alert(self, alert):
        """Save alert to the alerts file"""
        try:
            # Create alerts directory if it doesn't exist
            os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
            
            # Load existing alerts
            alerts = []
            if os.path.exists(self.alert_file):
                try:
                    with open(self.alert_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            alerts = data
                        elif isinstance(data, dict) and 'alerts' in data:
                            alerts = data['alerts']
                except json.JSONDecodeError:
                    # If file is corrupt, start with empty alerts
                    logger.warning(f"Alert file corrupt, starting fresh: {self.alert_file}")
            
            # Add new alert
            alerts.append(alert)
            
            # Save back to file
            with open(self.alert_file, 'w') as f:
                if isinstance(data, dict) and 'alerts' in data:
                    data['alerts'] = alerts
                    json.dump(data, f)
                else:
                    json.dump(alerts, f)
            
            logger.info(f"Saved alert to file: {self.alert_file}")
        
        except Exception as e:
            logger.error(f"Error saving alert to file: {str(e)}")
    
    def send_test_alert(self):
        """Send a test alert to verify connectivity"""
        test_alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "Test Alert",
            'description': "This is a test alert from the notification dashboard connector",
            'severity': 2,
            'process_name': "test.exe",
            'command_line': "test.exe --verify-connection",
            'pid': 0,
            'username': "system"
        }
        
        self.alert_queue.put(test_alert)
        logger.info("Sent test alert to dashboard")
        return test_alert
    
    def shutdown(self):
        """Shutdown the connector"""
        self.running = False
        
        if self.connected:
            try:
                self.sio.disconnect()
            except:
                pass
        
        if self.notification_orchestrator:
            self.notification_orchestrator.shutdown()
        
        logger.info("Notification dashboard connector shut down")

# Standalone usage for testing
if __name__ == "__main__":
    # Create connector
    connector = NotificationDashboardConnector()
    
    # Initialize orchestrator
    orchestrator = connector.initialize_orchestrator()
    
    # Send a test alert
    connector.send_test_alert()
    
    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Shutdown when interrupted
        connector.shutdown()