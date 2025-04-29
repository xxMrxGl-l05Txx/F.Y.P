import psutil
import logging
import sys
import os
from notification.notification_orchestrator import NotificationOrchestrator
from datetime import datetime
from database.connection import DatabaseConnection
from database.process_history import ProcessHistoryDB
from alerts.mongo_alert_method import MongoAlertMethod
from alerts.alert_system import AlertMethod
from alerts.alert_system import AlertManager
from database.process_history import ProcessHistoryDB
from database.connection import DatabaseConnection
from utils.environment_baseline import EnvironmentBaseline

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from alerts.alert_system import AlertManager

class ProcessMonitor:
    def __init__(self, config_file=None):
        # Initialize list of LOLBins to monitor
        self.watched_binaries = [
            'certutil.exe',
            'regsvr32.exe',
            'powershell.exe',
            'bitsadmin.exe',
            'mshta.exe',
            'wmic.exe',
            'rundll32.exe',   # Commonly used to execute malicious DLLs
            'odbcconf.exe',   # Can be used to execute DLLs
            'msiexec.exe',    # Can install malicious MSI packages remotely
            'forfiles.exe',   # Command execution through /c parameter
            'installutil.exe' # .NET binary that can bypass AppLocker
        ]
        
        # Setup basic logging
        self.setup_logging()
        
        self.process_history_db = ProcessHistoryDB()
        
        self.db_connection = DatabaseConnection.get_instance()
        self.db = self.db_connection.db
        
        # Initialize the rule engine
        self.rule_engine = RuleEngine()
        
        # Initialize the alert manager
        self.alert_manager = AlertManager(config_file)
        
        # Initialize environment baseline
        self.environment_baseline = EnvironmentBaseline()
        
        logging.info("Process Monitor initialized successfully")

        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'config', 'config.json')
        self.notification_orchestrator = NotificationOrchestrator(
            config_file=config_path if os.path.exists(config_path) else None
        )

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='lolbins_monitor.log'
        )
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    def _check_unusual_parent(self, process_info):
        """Check if process has an unusual parent process"""
        try:
            pid = process_info.get('pid')
            if not pid:
                return {"is_suspicious": False}
                
            # Get parent process
            process = psutil.Process(pid)
            parent = process.parent()
            
            if not parent:
                return {"is_suspicious": False}
                
            parent_name = parent.name().lower()
            process_name = process_info.get('name', '').lower()
            
            # Define suspicious parent-child relationships
            suspicious_parents = {
                "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe"],
                "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe"],
                "wmic.exe": ["powershell.exe", "excel.exe", "winword.exe"],
                "mshta.exe": ["excel.exe", "winword.exe", "powershell.exe"],
                "regsvr32.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "excel.exe", "winword.exe"],
                "rundll32.exe": ["powershell.exe", "wscript.exe", "excel.exe", "winword.exe"]
            }
            
            if process_name in suspicious_parents and parent_name in suspicious_parents[process_name]:
                logging.warning(f"Unusual parent process detected: {parent_name} -> {process_name}")
                return {
                    "parent_name": parent_name,
                    "parent_pid": parent.pid,
                    "is_suspicious": True
                }
                
            return {"is_suspicious": False}
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.debug(f"Error checking parent process: {str(e)}")
            return {"is_suspicious": False}

    def is_whitelisted(self, process_info):
        """
        Check if a process is whitelisted (known to be safe)
        """
        # This is a simple implementation - consider enhancing with a proper whitelist system
        # For now, we'll consider system processes in system directories as whitelisted
        try:
            process_name = process_info.get('name', '').lower()
            if not process_name:
                return False
                
            pid = process_info.get('pid')
            if not pid:
                return False
                
            process = psutil.Process(pid)
            try:
                exe_path = process.exe()
                # Check if process is running from system directories
                system_dirs = [
                    r"C:\Windows\System32",
                    r"C:\Windows\SysWOW64",
                    r"C:\Windows"
                ]
                return any(exe_path.startswith(dir) for dir in system_dirs)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return False
        except:
            return False

    def _analyze_process(self, process_info):
        """
        Analyze detected LOLBin process
        """
        try:
            # Store process in history collection
            process_doc = {
                "timestamp": datetime.now(),
                "process_name": process_info['name'].lower(),
                "command_line": ' '.join(process_info.get('cmdline', [])),
                "pid": process_info.get('pid', 0),
                "username": process_info.get('username', '')
            }
            
            self.db.process_history.insert_one(process_doc)
            
            # Get current timestamp for logging
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logging.info(f"LOLBin detected: {process_info['name']} (PID: {process_info['pid']}) at {current_time}")
            
            # Pass to rule engine for analysis
            alerts = self.rule_engine.analyze_process(process_info)
            
            self.process_history_db.add_process(process_info)
            
            # Check for unusual parent process
            parent_info = self._check_unusual_parent(process_info)
            if parent_info.get("is_suspicious", False):
                # Create alert for unusual parent process
                alert = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'rule_name': "Unusual Parent Process",
                    'description': f"Process {process_info['name']} spawned by suspicious parent {parent_info['parent_name']}",
                    'severity': 4,
                    'process_name': process_info['name'],
                    'command_line': ' '.join(process_info.get('cmdline', [])),
                    'pid': process_info.get('pid'),
                    'username': process_info.get('username', ''),
                    'parent_process': parent_info['parent_name'],
                    'parent_pid': parent_info['parent_pid']
                }
                logging.warning(f"Unusual parent process detected: {parent_info['parent_name']} -> {process_info['name']}")
                alerts.append(alert)
            
            # Check if process is anomalous based on environment baseline
            self.environment_baseline.add_observation(process_info)
            process_name = process_info['name']
            cmdline = ' '.join(process_info.get('cmdline', []))
            
            if not self.is_whitelisted(process_info) and self.environment_baseline.is_anomalous(process_info):
                # Create anomaly alert
                anomaly_alert = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'rule_name': "Unusual Process Activity",
                    'description': f"Process {process_name} showing anomalous behavior",
                    'severity': 2,  # Medium-low severity for anomalies
                    'process_name': process_name,
                    'command_line': cmdline,
                    'pid': process_info.get('pid'),
                    'username': process_info.get('username'),
                    'anomaly': True
                }
                logging.warning(f"Anomalous process activity: {process_name}")
                alerts.append(anomaly_alert)
            
            if alerts:
                logging.warning(f"ALERT: Found {len(alerts)} suspicious behaviors!")
                
                # Send alerts through the alert manager
                for alert in alerts:
                    self.alert_manager.send_alert(alert)
                    self.notification_orchestrator.process_alert(alert)
                    
                    # Still log the alert to our log file
                    log_message = (
                        f"SECURITY ALERT!\n"
                        f"Rule: {alert['rule_name']}\n"
                        f"Severity: {alert['severity']}/5\n"
                        f"Description: {alert['description']}\n"
                        f"Process: {alert['process_name']} (PID: {alert['pid']})\n"
                        f"User: {alert['username']}\n"
                        f"Command: {alert['command_line']}\n"
                        f"Timestamp: {alert['timestamp']}\n"
                        f"----------------------"
                    )
                    logging.warning(log_message)
            else:
                logging.info(f"No suspicious behavior detected for {process_info['name']}")
                
        except Exception as e:
            logging.error(f"Error analyzing process: {str(e)}")

    def start_continuous_monitoring(self, interval=5):
        """
        Start continuous monitoring with a specified interval
        
        Args:
            interval (int): Time in seconds between monitoring cycles
        """
        import time
        
        logging.info(f"Starting continuous monitoring (interval: {interval}s)")
        try:
            while True:
                self.monitor_processes()
                time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user")
        except Exception as e:
            logging.error(f"Error in continuous monitoring: {str(e)}")

if __name__ == "__main__":
    # Test the monitor
    monitor = ProcessMonitor()
    
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        # Get interval if provided
        interval = 5
        if len(sys.argv) > 2:
            try:
                interval = int(sys.argv[2])
            except ValueError:
                pass
        
        # Start continuous monitoring
        monitor.start_continuous_monitoring(interval)
    else:
        # Run once
        monitor.monitor_processes()