# import psutil
# import logging
# import sys
# import os
# from datetime import datetime

# # Add parent directory to path to import from other modules
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# from rules.rule_engine import RuleEngine

# class ProcessMonitor:
#     def __init__(self):
#         # Initialize list of LOLBins to monitor
#         self.watched_binaries = [
#             'certutil.exe',
#             'regsvr32.exe',
#             'powershell.exe',
#             'bitsadmin.exe',
#             'mshta.exe',
#             'wmic.exe'
#         ]
        
#         # Setup basic logging
#         self.setup_logging()
        
#         # Initialize the rule engine
#         self.rule_engine = RuleEngine()

#     def setup_logging(self):
#         logging.basicConfig(
#             level=logging.INFO,
#             format='%(asctime)s - %(levelname)s - %(message)s',
#             filename='lolbins_monitor.log'
#         )
#         # Also log to console
#         console = logging.StreamHandler()
#         console.setLevel(logging.INFO)
#         formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#         console.setFormatter(formatter)
#         logging.getLogger('').addHandler(console)

#     def monitor_processes(self):
#         """
#         Monitor system processes for LOLBins activity
#         """
#         logging.info("Starting LOLBins monitoring...")
#         try:
#             for proc in psutil.process_iter(['name', 'cmdline', 'pid', 'username']):
#                 try:
#                     if proc.info['name'] and proc.info['name'].lower() in self.watched_binaries:
#                         self._analyze_process(proc.info)
#                 except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
#                     continue
#         except Exception as e:
#             logging.error(f"Error in process monitoring: {str(e)}")

#     def _analyze_process(self, process_info):
#         """
#         Analyze detected LOLBin process
#         """
#         try:
#             timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             logging.info(f"LOLBin detected: {process_info['name']} (PID: {process_info['pid']})")
            
#             # Pass to rule engine for analysis
#             alerts = self.rule_engine.analyze_process(process_info)
            
#             if alerts:
#                 logging.warning(f"ALERT: Found {len(alerts)} suspicious behaviors!")
#                 for alert in alerts:
#                     log_message = (
#                         f"SECURITY ALERT!\n"
#                         f"Rule: {alert['rule_name']}\n"
#                         f"Severity: {alert['severity']}/5\n"
#                         f"Description: {alert['description']}\n"
#                         f"Process: {alert['process_name']} (PID: {alert['pid']})\n"
#                         f"User: {alert['username']}\n"
#                         f"Command: {alert['command_line']}\n"
#                         f"Timestamp: {alert['timestamp']}\n"
#                         f"----------------------"
#                     )
#                     logging.warning(log_message)
#             else:
#                 logging.info(f"No suspicious behavior detected for {process_info['name']}")
                
#         except Exception as e:
#             logging.error(f"Error analyzing process: {str(e)}")

# if __name__ == "__main__":
#     # Test the monitor
#     monitor = ProcessMonitor()
#     monitor.monitor_processes()

import psutil
import logging
import sys
import os
from datetime import datetime

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
            'wmic.exe'
        ]
        
        # Setup basic logging
        self.setup_logging()
        
        # Initialize the rule engine
        self.rule_engine = RuleEngine()
        
        # Initialize the alert manager
        self.alert_manager = AlertManager(config_file)
        
        logging.info("Process Monitor initialized successfully")

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

    def monitor_processes(self):
        """
        Monitor system processes for LOLBins activity
        """
        logging.info("Starting LOLBins monitoring...")
        try:
            for proc in psutil.process_iter(['name', 'cmdline', 'pid', 'username']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() in self.watched_binaries:
                        self._analyze_process(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    continue
        except Exception as e:
            logging.error(f"Error in process monitoring: {str(e)}")

    def _analyze_process(self, process_info):
        """
        Analyze detected LOLBin process
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logging.info(f"LOLBin detected: {process_info['name']} (PID: {process_info['pid']})")
            
            # Pass to rule engine for analysis
            alerts = self.rule_engine.analyze_process(process_info)
            
            if alerts:
                logging.warning(f"ALERT: Found {len(alerts)} suspicious behaviors!")
                
                # Send alerts through the alert manager
                for alert in alerts:
                    self.alert_manager.send_alert(alert)
                    
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