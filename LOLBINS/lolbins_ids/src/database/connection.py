# src/database/connection.py
import pymongo
from pymongo import MongoClient
import logging

class DatabaseConnection:
    _instance = None
    
    @staticmethod
    def get_instance(connection_string="mongodb://localhost:27017/", db_name="lolbins_ids"):
        """Singleton pattern to ensure one database connection"""
        if DatabaseConnection._instance is None:
            DatabaseConnection._instance = DatabaseConnection(connection_string, db_name)
        return DatabaseConnection._instance
    
    def __init__(self, connection_string, db_name):
        """Initialize database connection"""
        try:
            self.client = MongoClient(connection_string)
            self.db = self.client[db_name]
            logging.info(f"Connected to MongoDB database: {db_name}")
        except Exception as e:
            logging.error(f"Error connecting to MongoDB: {str(e)}")
            raise