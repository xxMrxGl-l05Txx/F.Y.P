# data_provider.py
import os
import json
import logging
from datetime import datetime, timedelta
import pandas as pd

class DataProvider:
    def __init__(self, alerts_file=None):
        """
        Initialize the data provider with the path to the alerts file
        
        Args:
            alerts_file (str): Path to the alerts JSON file
        """
        self.alerts_file = alerts_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            'alerts.json'
        )
        logging.info(f"Data provider initialized with alerts file: {self.alerts_file}")
    
    def get_all_alerts(self):
        """
        Get all alerts from the alerts file
        
        Returns:
            list: List of alert dictionaries
        """
        try:
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Error loading alerts: {str(e)}")
            return []
    
    def get_recent_alerts(self, hours=24):
        """
        Get alerts from the last specified hours
        
        Args:
            hours (int): Number of hours to look back
            
        Returns:
            list: List of recent alert dictionaries
        """
        try:
            alerts = self.get_all_alerts()
            cutoff = datetime.now() - timedelta(hours=hours)
            
            recent_alerts = []
            for alert in alerts:
                try:
                    alert_time = datetime.strptime(alert.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                    if alert_time >= cutoff:
                        recent_alerts.append(alert)
                except ValueError:
                    # Skip alerts with invalid timestamp
                    continue
                    
            return recent_alerts
        except Exception as e:
            logging.error(f"Error getting recent alerts: {str(e)}")
            return []
    
    def get_alerts_by_severity(self):
        """
        Count alerts by severity level
        
        Returns:
            dict: Dictionary with severity levels as keys and counts as values
        """
        try:
            alerts = self.get_all_alerts()
            severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
            
            for alert in alerts:
                severity = alert.get('severity', 0)
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    
            return severity_counts
        except Exception as e:
            logging.error(f"Error analyzing alerts by severity: {str(e)}")
            return {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    
    def get_alerts_by_lolbin(self):
        """
        Count alerts by LOLBin type
        
        Returns:
            dict: Dictionary with LOLBin names as keys and counts as values
        """
        try:
            alerts = self.get_all_alerts()
            lolbin_counts = {}
            
            for alert in alerts:
                process_name = alert.get('process_name', 'unknown')
                if process_name in lolbin_counts:
                    lolbin_counts[process_name] += 1
                else:
                    lolbin_counts[process_name] = 1
                    
            return lolbin_counts
        except Exception as e:
            logging.error(f"Error analyzing alerts by LOLBin: {str(e)}")
            return {}
    
    def get_alerts_by_date(self):
        """
        Count alerts by date
        
        Returns:
            dict: Dictionary with dates as keys and counts as values
        """
        try:
            alerts = self.get_all_alerts()
            date_counts = {}
            
            for alert in alerts:
                timestamp = alert.get('timestamp', '')
                if timestamp:
                    date = timestamp.split(' ')[0]
                    if date in date_counts:
                        date_counts[date] += 1
                    else:
                        date_counts[date] = 1
                    
            return date_counts
        except Exception as e:
            logging.error(f"Error analyzing alerts by date: {str(e)}")
            return {}
    
    def get_alerts_by_rule(self):
        """
        Count alerts by rule name
        
        Returns:
            dict: Dictionary with rule names as keys and counts as values
        """
        try:
            alerts = self.get_all_alerts()
            rule_counts = {}
            
            for alert in alerts:
                rule_name = alert.get('rule_name', 'unknown')
                if rule_name in rule_counts:
                    rule_counts[rule_name] += 1
                else:
                    rule_counts[rule_name] = 1
                    
            return rule_counts
        except Exception as e:
            logging.error(f"Error analyzing alerts by rule: {str(e)}")
            return {}
    
    def get_alerts_by_user(self):
        """
        Count alerts by username
        
        Returns:
            dict: Dictionary with usernames as keys and counts as values
        """
        try:
            alerts = self.get_all_alerts()
            user_counts = {}
            
            for alert in alerts:
                username = alert.get('username', 'unknown')
                if username in user_counts:
                    user_counts[username] += 1
                else:
                    user_counts[username] = 1
                    
            return user_counts
        except Exception as e:
            logging.error(f"Error analyzing alerts by user: {str(e)}")
            return {}

    def get_alerts_dataframe(self):
        """
        Convert alerts to a pandas DataFrame for analysis
        
        Returns:
            DataFrame: Pandas DataFrame containing alert data
        """
        try:
            alerts = self.get_all_alerts()
            if not alerts:
                return pd.DataFrame()
                
            df = pd.DataFrame(alerts)
            return df
        except Exception as e:
            logging.error(f"Error converting alerts to DataFrame: {str(e)}")
            return pd.DataFrame()
    
    def get_alerts_summary(self):
        """
        Generate a summary of all alert data
        
        Returns:
            dict: Dictionary containing summary statistics
        """
        try:
            alerts = self.get_all_alerts()
            
            if not alerts:
                return {
                    "total_alerts": 0,
                    "high_severity_alerts": 0,
                    "recent_alerts": 0,
                    "most_common_lolbin": "None",
                    "most_triggered_rule": "None"
                }
            
            # Count high severity alerts (4-5)
            high_severity = sum(1 for alert in alerts if alert.get('severity', 0) >= 4)
            
            # Count recent alerts (last 24 hours)
            recent = len(self.get_recent_alerts(hours=24))
            
            # Get most common LOLBin
            lolbin_counts = self.get_alerts_by_lolbin()
            most_common_lolbin = max(lolbin_counts.items(), key=lambda x: x[1])[0] if lolbin_counts else "None"
            
            # Get most triggered rule
            rule_counts = self.get_alerts_by_rule()
            most_triggered_rule = max(rule_counts.items(), key=lambda x: x[1])[0] if rule_counts else "None"
            
            return {
                "total_alerts": len(alerts),
                "high_severity_alerts": high_severity,
                "recent_alerts": recent,
                "most_common_lolbin": most_common_lolbin,
                "most_triggered_rule": most_triggered_rule
            }
        except Exception as e:
            logging.error(f"Error generating alerts summary: {str(e)}")
            return {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "recent_alerts": 0,
                "most_common_lolbin": "Error",
                "most_triggered_rule": "Error"
            }

# Test the data provider
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    provider = DataProvider()
    alerts = provider.get_all_alerts()
    logging.info(f"Loaded {len(alerts)} alerts")
    
    summary = provider.get_alerts_summary()
    logging.info(f"Alerts summary: {summary}")