# src/utils/security_analysis.py
from database.connection import DatabaseConnection
import pymongo
from datetime import datetime, timedelta

class SecurityAnalysis:
    def __init__(self):
        connection = DatabaseConnection.get_instance()
        self.db = connection.db
    
    def find_suspicious_patterns(self, days=7):
        """Find suspicious patterns in the collected data"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_date_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
        # Find users with high alert counts
        user_alerts = list(self.db.alerts.aggregate([
            {"$match": {"timestamp": {"$gte": start_date_str}}},
            {"$group": {"_id": "$username", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        
        # Find potentially compromised systems
        # (multiple high severity alerts in short time)
        high_severity_hosts = list(self.db.alerts.aggregate([
            {"$match": {
                "timestamp": {"$gte": start_date_str},
                "severity": {"$gte": 4}
            }},
            {"$group": {"_id": "$username", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gte": 3}}},
            {"$sort": {"count": -1}}
        ]))
        
        # Identify potential attack chains 
        # (looking for process sequences that match common attack patterns)
        # This is a simplified example - real implementation would be more complex
        attack_sequences = {}
        for username in [user["_id"] for user in user_alerts]:
            processes = list(self.db.process_history.find(
                {"username": username, "timestamp": {"$gte": start_date}},
                sort=[("timestamp", 1)]
            ))
            
            # Look for download then execute patterns
            download_processes = [p for p in processes if any(term in p.get("command_line", "").lower() 
                                  for term in ["download", "urlcache", "transfer"])]
            
            for dp in download_processes:
                # Look for execution after download
                download_time = dp["timestamp"]
                executions = [p for p in processes if p["timestamp"] > download_time 
                             and p["process_name"] != dp["process_name"]]
                
                if executions:
                    attack_sequences[username] = {
                        "download": dp,
                        "execution": executions[0],
                        "time_between": (executions[0]["timestamp"] - download_time).total_seconds()
                    }
        
        return {
            "suspicious_users": user_alerts,
            "compromised_hosts": high_severity_hosts,
            "attack_chains": attack_sequences
        }
    
    def get_alert_timeline(self, username=None, days=7):
        """Get timeline of alerts for analysis"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        match_query = {"timestamp": {"$gte": start_date.strftime("%Y-%m-%d %H:%M:%S")}}
        if username:
            match_query["username"] = username
            
        pipeline = [
            {"$match": match_query},
            {"$project": {
                "day": {"$substr": ["$timestamp", 0, 10]},
                "severity": 1,
                "rule_name": 1
            }},
            {"$group": {
                "_id": {"day": "$day", "severity": "$severity"},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.day": 1, "_id.severity": -1}}
        ]
        
        return list(self.db.alerts.aggregate(pipeline))