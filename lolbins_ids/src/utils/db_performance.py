# src/analysis/threat_analyzer.py
from src.database.connection import DatabaseConnection
import pymongo
from datetime import datetime, timedelta

class ThreatAnalyzer:
    def __init__(self):
        connection = DatabaseConnection.get_instance()
        self.db = connection.db
    
    def get_attack_patterns(self, days=7):
        """Find potential attack patterns based on process sequences"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
        # Find users with multiple LOLBin executions
        users = list(self.db.process_history.aggregate([
            {"$match": {"timestamp": {"$gte": start_str}}},
            {"$group": {"_id": "$username", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gt": 3}}},  # Users with significant activity
            {"$project": {"_id": 1}}  # Just get usernames
        ]))
        
        patterns = []
        for user in users:
            username = user["_id"]
            # Get process sequence for this user
            processes = list(self.db.process_history.find(
                {"username": username, "timestamp": {"$gte": start_str}},
                sort=[("timestamp", 1)]
            ))
            
            # Look for download followed by execution pattern
            for i in range(len(processes)-1):
                current = processes[i]
                next_proc = processes[i+1]
                
                # Check for download operations
                if any(term in current.get("command_line", "").lower() 
                      for term in ["download", "urlcache", "transfer"]):
                    # Check if followed by execution
                    time_diff = (next_proc["timestamp"] - current["timestamp"]).total_seconds()
                    if time_diff < 300:  # Within 5 minutes
                        patterns.append({
                            "username": username,
                            "download_process": current,
                            "execution_process": next_proc,
                            "time_between": time_diff
                        })
        
        return patterns