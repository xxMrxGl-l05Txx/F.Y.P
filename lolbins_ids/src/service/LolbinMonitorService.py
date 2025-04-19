# LolbinMonitorService.py
# A Windows service to continuously monitor for LOLBin attacks

import os
import sys
import time
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import threading
import queue
import pythoncom
import win32com.client
import winerror
from pathlib import Path

# Add parent directory to path to import other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from monitor.process_monitor import ProcessMonitor
from alerts.alert_system import AlertManager
from rules.enhanced_rule_engine import EnhancedRuleEngine
from utils.performance_monitor import PerformanceMonitor
from notification.notification_orchestrator import NotificationOrchestrator

class LolbinMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "LolbinIdsMonitor"
    _svc_display_name_ = "LOLBin IDS Monitoring Service"
    _svc_description_ = "Monitors Windows processes for LOLBin attack techniques"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_running = False
        
        # Set up logging
        log_dir = Path("C:/ProgramData/LolbinIDS/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = log_dir / "lolbin_service.log"
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=str(self.log_file)
        )
        
        # Initialize alert queue for passing to notification system
        self.alert_queue = queue.Queue()
        
    def SvcStop(self):
        """Called when the service is asked to stop"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        logging.info('Service stop request received')
        self.is_running = False
        
    def SvcDoRun(self):
        """Main service entry point when started"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PID_INFO,
            (self._svc_name_, 'Starting service')
        )
        
        # Initialize monitoring thread
        self.is_running = True
        self.main_thread = threading.Thread(target=self.run_monitoring)
        self.main_thread.daemon = True
        self.main_thread.start()
        
        # Wait for service stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        
        logging.info('Service is shutting down')
        # Wait for thread to finish
        if self.main_thread.is_alive():
            self.main_thread.join(timeout=5.0)
        
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PID_INFO,
            (self._svc_name_, 'Service stopped')
        )
        
    def run_monitoring(self):
        """Run the monitoring loop in a separate thread"""
        try:
            logging.info("Initializing monitoring components")
            
            # Load configuration
            config_path = Path("C:/ProgramData/LolbinIDS/config.json")
            
            # Initialize components
            self.rule_engine = EnhancedRuleEngine(
                config_file=str(config_path) if config_path.exists() else None
            )
            
            self.alert_manager = AlertManager(
                config_file=str(config_path) if config_path.exists() else None
            )
            
            # Initialize the process monitor
            self.process_monitor = ProcessMonitor(
                config_file=str(config_path) if config_path.exists() else None
            )
            
            # Initialize performance monitor
            self.performance_monitor = PerformanceMonitor(
                output_file="C:/ProgramData/LolbinIDS/performance_stats.json"
            )
            self.performance_monitor.start_monitoring(interval=60)  # 1-minute intervals for stats
            
            # Initialize notification orchestrator
            self.notification_orchestrator = NotificationOrchestrator(
                config_file=str(config_path) if config_path.exists() else None,
                alert_queue=self.alert_queue
            )
            
            # Start notification thread
            self.notification_thread = threading.Thread(target=self.process_notifications)
            self.notification_thread.daemon = True
            self.notification_thread.start()
            
            # Custom alert handler to route alerts to notification system
            def alert_handler(alert_data):
                # Process through regular alert manager
                self.alert_manager.send_alert(alert_data)
                
                # Also add to notification queue
                self.alert_queue.put(alert_data)
                
                # Record performance metrics
                self.performance_monitor.record_alert(alert_data.get('rule_name', 'Unknown'))
                
                return True
            
            # Inject our custom handler into the process monitor
            self.process_monitor.custom_alert_handler = alert_handler
            
            # Run continuous monitoring with a 5-second interval
            logging.info("Starting continuous monitoring")
            monitoring_interval = 5  # seconds
            
            while self.is_running:
                try:
                    # Get the start time to measure performance
                    start_time = time.time()
                    
                    # Run a monitoring cycle
                    self.process_monitor.monitor_processes()
                    
                    # Record execution time
                    execution_time = time.time() - start_time
                    self.performance_monitor.record_process_analysis(execution_time)
                    
                    # Sleep for the remaining interval time
                    sleep_time = max(0.1, monitoring_interval - execution_time)
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    logging.error(f"Error in monitoring cycle: {str(e)}")
                    time.sleep(monitoring_interval)  # Sleep and retry
            
            # Stop performance monitoring
            self.performance_monitor.stop_monitoring()
            
            logging.info("Monitoring stopped")
            
        except Exception as e:
            logging.error(f"Critical error in monitoring thread: {str(e)}")
            servicemanager.LogErrorMsg(f"Critical error in LOLBin IDS service: {str(e)}")
            
    def process_notifications(self):
        """Process alerts from the queue and send to notification system"""
        try:
            logging.info("Starting notification processing thread")
            
            while self.is_running:
                try:
                    # Get alert with a timeout so we can check if service is still running
                    try:
                        alert = self.alert_queue.get(timeout=1.0)
                    except queue.Empty:
                        continue
                    
                    # Process the alert through the notification orchestrator
                    self.notification_orchestrator.process_alert(alert)
                    
                    # Mark as done
                    self.alert_queue.task_done()
                    
                except Exception as e:
                    logging.error(f"Error processing notification: {str(e)}")
                    
            logging.info("Notification thread stopped")
            
        except Exception as e:
            logging.error(f"Critical error in notification thread: {str(e)}")

def install_and_start_service():
    """Helper function to install and start the service"""
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(LolbinMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(LolbinMonitorService)

if __name__ == '__main__':
    install_and_start_service()