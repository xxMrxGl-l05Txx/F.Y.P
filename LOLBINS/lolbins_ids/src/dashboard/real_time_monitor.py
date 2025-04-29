# src/dashboard/real_time_monitor.py
from src.database.connection import DatabaseConnection
import threading
import logging

class RealTimeMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        connection = DatabaseConnection.get_instance()
        self.db = connection.db
        self.running = True
        self.callbacks = []
    
    def add_callback(self, callback):
        """Add a callback function to be called when new alerts arrive"""
        self.callbacks.append(callback)
    
    def run(self):
        """Monitor for new alerts using MongoDB change streams"""
        try:
            # Watch the alerts collection for new documents
            pipeline = [{'$match': {'operationType': 'insert'}}]
            with self.db.alerts.watch(pipeline) as stream:
                while self.running:
                    change = stream.try_next()
                    if change:
                        # New alert received
                        alert_data = change['fullDocument']
                        logging.info(f"New alert detected: {alert_data['rule_name']}")
                        
                        # Call all registered callbacks
                        for callback in self.callbacks:
                            try:
                                callback(alert_data)
                            except Exception as e:
                                logging.error(f"Error in callback: {str(e)}")
        except Exception as e:
            logging.error(f"Error in change stream: {str(e)}")
    
    def stop(self):
        """Stop the monitor thread"""
        self.running = False