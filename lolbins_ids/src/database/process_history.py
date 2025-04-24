# src/database/process_history.py
import pymongo
from pymongo import MongoClient
from datetime import datetime
import logging

class ProcessHistoryDB:
    def __init__(self, connection_string="mongodb://localhost:27017/", db_name="lolbins_ids"):
        """Initialize the process history database connection"""
        try:
            self.client = MongoClient(connection_string)
            self.db = self.client[db_name]
            self.history_collection = self.db["process_history"]
            
            # Create indexes for better performance
            self.history_collection.create_index("timestamp")
            self.history_collection.create_index("username")
            self.history_collection.create_index("process_name")
            
            logging.info("Process history database initialized")
        except Exception as e:
            logging.error(f"Error initializing process history database: {str(e)}")
            raise
        
    def add_process(self, process_info):
        """Add process to history database"""
        try:
            document = {
                "timestamp": datetime.now(),
                "process_name": process_info.get("name", "").lower(),
                "command_line": " ".join(process_info.get("cmdline", [])),
                "pid": process_info.get("pid", 0),
                "username": process_info.get("username", "")
            }
            self.history_collection.insert_one(document)
            logging.debug(f"Added process {document['process_name']} to history for user {document['username']}")
        except Exception as e:
            logging.error(f"Error adding process to history: {str(e)}")
    
    def get_user_context(self, username, limit=10):
        """Get recent processes for a user"""
        try:
            processes = list(self.history_collection.find(
                {"username": username},
                {"_id": 0, "process_name": 1, "timestamp": 1},
                sort=[("timestamp", pymongo.DESCENDING)],
                limit=limit
            ))
            return [p["process_name"] for p in processes]
        except Exception as e:
            logging.error(f"Error retrieving user context: {str(e)}")
            return []