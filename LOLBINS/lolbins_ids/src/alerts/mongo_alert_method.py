import logging
import sys
import os
from src.alerts.alert_system import AlertMethod  # Change this line
import logging
from src.database.connection import DatabaseConnection  # Also update this import

# Add the project root directory to path for running directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import the AlertMethod class directly from alert_system
from src.alerts.alert_system import AlertMethod
from src.database.connection import DatabaseConnection


class MongoAlertMethod(AlertMethod):
    """Alert method that saves to MongoDB"""
    def __init__(self, db_connection=None):
        if db_connection:
            self.db = db_connection.db
        else:
            connection = DatabaseConnection.get_instance()
            self.db = connection.db
        
        self.alerts_collection = self.db["alerts"]
        
        # Create indexes for better querying
        self.alerts_collection.create_index("timestamp")
        self.alerts_collection.create_index("severity")
        self.alerts_collection.create_index("rule_name")
        self.alerts_collection.create_index("process_name")
        self.alerts_collection.create_index([("command_line", "text")])  # Text search capabilities

    def send_alert(self, alert_data):
        try:
            result = self.alerts_collection.insert_one(alert_data)
            logging.info(f"Alert saved to MongoDB with ID: {result.inserted_id}")
            return True
        except Exception as e:
            logging.error(f"Error writing alert to MongoDB: {str(e)}")
            return False