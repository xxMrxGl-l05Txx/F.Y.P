# Create a test script called test_mongodb.py
import sys
import os
import logging
from datetime import datetime

# Add the project root directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database.connection import DatabaseConnection
from src.database.process_history import ProcessHistoryDB
from src.alerts.mongo_alert_method import MongoAlertMethod

try:
    from src.alerts.mongo_alert_method import MongoAlertMethod
except ImportError as e:
    logging.warning(f"Could not import MongoAlertMethod: {e}")
    # Define a simple version for testing
    class MongoAlertMethod:
        def __init__(self):
            self.db = DatabaseConnection.get_instance().db
            self.alerts_collection = self.db["alerts"]
            
        def send_alert(self, alert_data):
            try:
                result = self.alerts_collection.insert_one(alert_data)
                logging.info(f"Test alert saved to MongoDB with ID: {result.inserted_id}")
                return True
            except Exception as e:
                logging.error(f"Error: {str(e)}")
                return False

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

def test_mongodb_connection():
    """Test basic MongoDB connection"""
    try:
        connection = DatabaseConnection.get_instance()
        # Simple ping test
        connection.client.admin.command('ping')
        logging.info("✅ MongoDB connection successful")
        return connection
    except Exception as e:
        logging.error(f"❌ MongoDB connection failed: {str(e)}")
        return None

def test_process_history():
    """Test process history functionality"""
    db = ProcessHistoryDB()
    
    # Test adding process
    test_process = {
        'name': 'powershell.exe',
        'cmdline': ['powershell.exe', '-noexit', '-command', 'Get-Process'],
        'pid': 9999,
        'username': 'test_user'
    }
    
    db.add_process(test_process)
    logging.info("✅ Added test process to history")
    
    # Test retrieving processes
    processes = db.get_user_context('test_user')
    logging.info(f"✅ Retrieved {len(processes)} processes for test_user")
    logging.info(f"Process list: {processes}")

def test_alert_storage():
    """Test alert storage functionality"""
    alert_method = MongoAlertMethod()
    
    # Create test alert
    test_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "Test MongoDB Rule",
        'description': "Testing MongoDB alert storage",
        'severity': 3,
        'process_name': "test.exe",
        'command_line': "test.exe -test -args",
        'pid': 1234,
        'username': "test_user"
    }
    
    result = alert_method.send_alert(test_alert)
    if result:
        logging.info("✅ Successfully stored test alert in MongoDB")
    else:
        logging.error("❌ Failed to store test alert")

if __name__ == "__main__":
    logging.info("Testing MongoDB implementation...")
    
    # Test connection
    connection = test_mongodb_connection()
    if connection:
        # Test process history
        test_process_history()
        
        # Test alert storage
        test_alert_storage()