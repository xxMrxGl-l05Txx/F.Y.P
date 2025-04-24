# src/database/rule_storage.py
import logging
from database.connection import DatabaseConnection

class RuleStorage:
    def __init__(self, db_connection=None):
        if db_connection:
            self.db = db_connection.db
        else:
            connection = DatabaseConnection.get_instance()
            self.db = connection.db
            
        self.rules_collection = self.db["rules"]
        self.rules_collection.create_index("lolbin")
        self.rules_collection.create_index("name", unique=True)
    
    def save_rule(self, rule):
        """Save a rule to the database"""
        rule_doc = {
            "name": rule.name,
            "description": rule.description,
            "lolbin": rule.lolbin,
            "pattern": rule.pattern.pattern,  # Store the pattern string
            "severity": rule.severity,
            "required_args": rule.required_args,
            "whitelist_patterns": [p.pattern for p in rule.whitelist_patterns],
            "context_required": rule.context_required
        }
        
        try:
            # Upsert - update if exists, insert if not
            self.rules_collection.update_one(
                {"name": rule.name},
                {"$set": rule_doc},
                upsert=True
            )
            return True
        except Exception as e:
            logging.error(f"Error saving rule to database: {str(e)}")
            return False
    
    def get_rules(self, lolbin=None):
        """Get rules from database, optionally filtered by LOLBin"""
        query = {}
        if lolbin:
            query["lolbin"] = lolbin.lower()
            
        try:
            return list(self.rules_collection.find(query))
        except Exception as e:
            logging.error(f"Error retrieving rules from database: {str(e)}")
            return []