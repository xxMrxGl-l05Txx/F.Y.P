import logging
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

class EnvironmentBaseline:
    """Establishes baseline of normal system behavior to reduce false positives"""
    
    def __init__(self, db_path="baseline.json", learning_period_days=7):
        self.db_path = db_path
        self.learning_period = learning_period_days
        self.learning_mode = True
        self.start_time = datetime.now()
        self.baseline = self._load_baseline()
        
    def _load_baseline(self):
        """Load baseline from file or create a new one"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    # Check if learning is complete
                    if data.get('learning_complete', False):
                        self.learning_mode = False
                    return data
            except Exception as e:
                logging.error(f"Error loading baseline: {str(e)}")
        
        # Create new baseline structure
        return {
            "learning_start": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "learning_complete": False,
            "commands": defaultdict(int),
            "process_user_map": defaultdict(list),
            "hourly_activity": defaultdict(lambda: defaultdict(int)),
            "common_sequences": []
        }
    
    def save_baseline(self):
        """Save baseline to file"""
        try:
            # Check if learning period is complete
            days_elapsed = (datetime.now() - self.start_time).days
            if self.learning_mode and days_elapsed >= self.learning_period:
                self.baseline["learning_complete"] = True
                self.learning_mode = False
                logging.info(f"Baseline learning completed after {days_elapsed} days")
            
            with open(self.db_path, 'w') as f:
                json.dump(self.baseline, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Error saving baseline: {str(e)}")
            return False
    
    def add_observation(self, process_info):
        """Add process observation to baseline during learning period"""
        if not self.learning_mode:
            return False
            
        try:
            process_name = process_info.get('name', '').lower()
            username = process_info.get('username', '')
            cmdline = ' '.join(process_info.get('cmdline', []))
            
            # Update command frequency
            self.baseline["commands"][cmdline] += 1
            
            # Update process-user mapping
            if username and username not in self.baseline["process_user_map"].get(process_name, []):
                self.baseline["process_user_map"][process_name].append(username)
            
            # Update hourly activity
            current_hour = datetime.now().hour
            self.baseline["hourly_activity"][process_name][str(current_hour)] += 1
            
            # Periodically save baseline
            if self.baseline["commands"][cmdline] % 100 == 0:
                self.save_baseline()
                
            return True
        except Exception as e:
            logging.error(f"Error adding observation: {str(e)}")
            return False
    
    def is_anomalous(self, process_info):
        """Check if process activity is anomalous compared to baseline"""
        if self.learning_mode:
            return False  # No anomaly detection during learning
            
        try:
            process_name = process_info.get('name', '').lower()
            username = process_info.get('username', '')
            cmdline = ' '.join(process_info.get('cmdline', []))
            current_hour = datetime.now().hour
            
            # Check if user commonly runs this process
            if username and process_name in self.baseline["process_user_map"]:
                if username not in self.baseline["process_user_map"][process_name]:
                    return True
            
            # Check if process is run at unusual hour
            if process_name in self.baseline["hourly_activity"]:
                hourly_counts = self.baseline["hourly_activity"][process_name]
                if str(current_hour) not in hourly_counts or hourly_counts[str(current_hour)] < 5:
                    # This process is rarely run during this hour
                    return True
            
            # Command line never seen before
            if cmdline not in self.baseline["commands"]:
                return True
                
            return False
        except Exception as e:
            logging.error(f"Error checking anomaly: {str(e)}")
            return False