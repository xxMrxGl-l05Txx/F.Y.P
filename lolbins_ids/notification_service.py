# notification_service.py
import os
import sys
import time
import logging
import signal
import argparse
from datetime import datetime

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import components
from src.notification.notification_orchestrator import NotificationOrchestrator
from src.dashboard.notification_dashboard_connector import NotificationDashboardConnector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(current_dir, 'notification_service.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('notification_service')

class NotificationService:
    """Service to receive and process security alerts and forward to dashboard"""
    
    def __init__(self, dashboard_url='http://localhost:5000', config_file=None):
        self.dashboard_url = dashboard_url
        self.config_file = config_file
        self.connector = None
        self.orchestrator = None
        self.running = False
        
        # Signal handlers
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        
        logger.info("Notification service initialized")
    
    def handle_signal(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()
    
    def start(self):
        """Start the notification service"""
        try:
            logger.info("Starting notification service...")
            self.running = True
            
            # Initialize connector
            self.connector = NotificationDashboardConnector(
                dashboard_url=self.dashboard_url
            )
            
            # Initialize orchestrator through connector
            self.orchestrator = self.connector.initialize_orchestrator(
                config_file=self.config_file
            )
            
            if not self.orchestrator:
                logger.error("Failed to initialize notification orchestrator")
                return False
            
            # Send a startup notification
            self._send_startup_notification()
            
            logger.info("Notification service started successfully")
            
            # Keep running until stopped
            while self.running:
                time.sleep(1)
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting notification service: {str(e)}")
            self.shutdown()
            return False
    
    def _send_startup_notification(self):
        """Send a startup notification to confirm the service is working"""
        startup_alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "Service Started",
            'description': "The LOLBins IDS notification service has started successfully.",
            'severity': 1,
            'process_name': "notification_service.py",
            'command_line': "notification_service.py --dashboard-url http://localhost:5000",
            'pid': os.getpid(),
            'username': os.getlogin() if hasattr(os, 'getlogin') else 'system'
        }
        
        # Send through orchestrator
        if self.orchestrator:
            self.orchestrator.process_alert(startup_alert)
            logger.info("Sent startup notification")
    
    def shutdown(self):
        """Shutdown the notification service"""
        logger.info("Shutting down notification service...")
        self.running = False
        
        if self.connector:
            self.connector.shutdown()
        
        logger.info("Notification service shutdown complete")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='LOLBins IDS Notification Service')
    parser.add_argument('--dashboard-url', 
                      default='http://localhost:5000',
                      help='URL of the dashboard (default: http://localhost:5000)')
    parser.add_argument('--config',
                      default=None,
                      help='Path to configuration file')
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    logger.info("======== LOLBins IDS Notification Service ========")
    logger.info(f"Dashboard URL: {args.dashboard_url}")
    logger.info(f"Config file: {args.config if args.config else 'Default'}")
    
    # Create and start service
    service = NotificationService(
        dashboard_url=args.dashboard_url,
        config_file=args.config
    )
    
    # Run the service
    success = service.start()
    
    # Exit with appropriate status
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())