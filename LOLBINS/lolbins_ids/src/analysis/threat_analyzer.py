# src/analysis/threat_analyzer.py
import sys
import os
# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# Now you can use the full src path
from src.database.connection import DatabaseConnection
import pymongo
from datetime import datetime, timedelta

class ThreatAnalyzer:
    def __init__(self):
        connection = DatabaseConnection.get_instance()
        self.db = connection.db
    
    def get_high_risk_users(self, days=7, min_severity=4):
        """Find users with high severity alerts"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
        return list(self.db.alerts.aggregate([
            {"$match": {
                "timestamp": {"$gte": start_str},
                "severity": {"$gte": min_severity}
            }},
            {"$group": {
                "_id": "$username",
                "count": {"$sum": 1},
                "max_severity": {"$max": "$severity"},
                "alerts": {"$push": {
                    "rule_name": "$rule_name",
                    "timestamp": "$timestamp",
                    "process_name": "$process_name",
                    "severity": "$severity"
                }}
            }},
            {"$sort": {"count": -1}}
        ]))
    
    def get_common_lolbin_usage(self, days=7):
        """Get statistics on LOLBin usage patterns"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
        # Get LOLBin usage by type
        lolbin_stats = list(self.db.process_history.aggregate([
            {"$match": {"timestamp": {"$gte": start_str}}},
            {"$group": {"_id": "$process_name", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]))
        
        # Get users with most LOLBin activity
        user_activity = list(self.db.process_history.aggregate([
            {"$match": {"timestamp": {"$gte": start_str}}},
            {"$group": {"_id": "$username", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        
        # Get time patterns (hour of day statistics)
        hour_patterns = list(self.db.process_history.aggregate([
            {"$match": {"timestamp": {"$gte": start_str}}},
            {"$project": {
                "hour": {"$substr": ["$timestamp", 11, 2]}
            }},
            {"$group": {"_id": "$hour", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))
        
        return {
            "lolbin_stats": lolbin_stats,
            "user_activity": user_activity,
            "hour_patterns": hour_patterns
        }
    
    def get_mitre_attack_summary(self, days=7):
        """Summarize MITRE ATT&CK techniques observed"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        
        # Only process alerts that have MITRE ATT&CK information
        mitre_data = list(self.db.alerts.aggregate([
            {"$match": {
                "timestamp": {"$gte": start_str},
                "mitre_attack": {"$exists": True}
            }},
            {"$group": {
                "_id": {
                    "technique_id": "$mitre_attack.technique_id",
                    "technique_name": "$mitre_attack.technique_name"
                },
                "count": {"$sum": 1},
                "tactic": {"$first": "$mitre_attack.tactic"},
                "alerts": {"$push": {
                    "rule_name": "$rule_name",
                    "process_name": "$process_name",
                    "severity": "$severity"
                }}
            }},
            {"$sort": {"count": -1}}
        ]))
        
        # Group by tactic
        tactics = {}
        for item in mitre_data:
            tactic = item["tactic"]
            if tactic not in tactics:
                tactics[tactic] = []
            
            tactics[tactic].append({
                "technique_id": item["_id"]["technique_id"],
                "technique_name": item["_id"]["technique_name"],
                "count": item["count"],
                "alerts": item["alerts"][:5]  # Limit to 5 examples
            })
        
        return tactics
        
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