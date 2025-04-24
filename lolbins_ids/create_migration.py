# create_migration.py
import json
import sys
import os
import logging
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.connection import DatabaseConnection

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

def migrate_alerts(alerts_file):
    """Migrate alerts from a JSON file to MongoDB"""
    try:
        # Load existing alerts
        with open(alerts_file, 'r') as f:
            data = json.load(f)
            
        if isinstance(data, dict) and "alerts" in data:
            alerts = data["alerts"]
        elif isinstance(data, list):
            alerts = data
        else:
            logging.error("Unexpected JSON format in alerts file")
            return
            
        # Connect to MongoDB
        connection = DatabaseConnection.get_instance()
        db = connection.db
        alerts_collection = db["alerts"]
        
        # Insert alerts
        if alerts:
            result = alerts_collection.insert_many(alerts)
            logging.info(f"✅ Migrated {len(result.inserted_ids)} alerts to MongoDB")
        else:
            logging.info("No alerts to migrate")
            
    except Exception as e:
        logging.error(f"Migration error: {str(e)}")

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python migrate_alerts.py <alerts_file.json>")
        sys.exit(1)
        
    alerts_file = sys.argv[1]
    if not os.path.exists(alerts_file):
        print(f"Error: File {alerts_file} not found")
        sys.exit(1)
        
    migrate_alerts(alerts_file)