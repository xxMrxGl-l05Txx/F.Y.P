import logging
import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pymongo
from pymongo import MongoClient

class AlertManager:
    """
    Manages different alert methods and alert distribution
    """
    def __init__(self, config_file=None):
        """
        Initialize the alert manager
        
        Args:
            config_file (str): Path to configuration file (optional)
        """
        self.alert_methods = []
        self.config = self._load_config(config_file)
        self._setup_alert_methods()
        
        logging.info(f"Alert Manager initialized with {len(self.alert_methods)} alert methods")
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            "alert_methods": {
                "console": True,
                "file": True,
                "email": False,
                "mongodb": True  # Enable MongoDB by default
            },
            "email_config": {
                "server": "smtp.gmail.com",
                "port": 587,
                "username": "",
                "password": "",
                "recipients": []
            },
            "mongodb_config": {
                "connection_string": "mongodb://localhost:27017/",
                "db_name": "lolbins_ids"
            },
            "alert_levels": ["critical", "high", "medium"],  # Which severity levels to alert on
            "alert_file": "alerts.json"
        }
        
        # Debug output
        logging.info(f"Looking for config file: {config_file}")
        
        if config_file and os.path.exists(config_file):
            try:
                logging.info(f"Found config file: {config_file}")
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                logging.info(f"Loaded config: {json.dumps(loaded_config, indent=2)}")
                return loaded_config
            except Exception as e:
                logging.error(f"Error loading config file: {str(e)}")
                return default_config
        else:
            if config_file:
                logging.info(f"Config file not found: {config_file}")
            else:
                logging.info("No config file specified, using defaults")
            return default_config
    
    def _setup_alert_methods(self):
        """Setup alert methods based on configuration"""
        if self.config["alert_methods"].get("console", True):
            self.alert_methods.append(ConsoleAlertMethod())
            logging.info("Console alert method enabled")
        
        if self.config["alert_methods"].get("file", True):
            self.alert_methods.append(
                FileAlertMethod(self.config.get("alert_file", "alerts.json"))
            )
            logging.info("File alert method enabled")
        
        if self.config["alert_methods"].get("email", False):
            email_config = self.config.get("email_config", {})
            if all(k in email_config for k in ["server", "port", "username", "password", "recipients"]):
                self.alert_methods.append(EmailAlertMethod(
                    server=email_config["server"],
                    port=email_config["port"],
                    username=email_config["username"],
                    password=email_config["password"],
                    recipients=email_config["recipients"]
                ))
                logging.info("Email alert method enabled")
            else:
                logging.warning("Email alerting disabled: Missing configuration parameters")
        
        # Add MongoDB alert method
        if self.config["alert_methods"].get("mongodb", True):  # Enable by default
            mongodb_config = self.config.get("mongodb_config", {})
            connection_string = mongodb_config.get("connection_string", "mongodb://localhost:27017/")
            db_name = mongodb_config.get("db_name", "lolbins_ids")
            try:
                self.alert_methods.append(MongoDBAlertMethod(
                    connection_string=connection_string,
                    db_name=db_name
                ))
                logging.info("MongoDB alert method enabled")
            except Exception as e:
                logging.error(f"Failed to initialize MongoDB alert method: {str(e)}")
    
    def should_alert(self, severity):
        """
        Determine if an alert should be sent based on severity and configuration
        
        Args:
            severity (int): Severity level of the alert (1-5)
            
        Returns:
            bool: True if alert should be sent, False otherwise
        """
        # Map severity number to level
        severity_map = {
            5: "critical",
            4: "high",
            3: "medium",
            2: "low",
            1: "info"
        }
        
        severity_level = severity_map.get(severity, "info")
        return severity_level in self.config["alert_levels"]
    
    def send_alert(self, alert_data):
        """
        Send alert through all configured alert methods
        
        Args:
            alert_data (dict): Alert information dictionary
        """
        if not self.should_alert(alert_data.get("severity", 0)):
            logging.debug(f"Alert suppressed - severity {alert_data.get('severity')} below threshold")
            return
            
        for method in self.alert_methods:
            try:
                method.send_alert(alert_data)
            except Exception as e:
                logging.error(f"Error sending alert via {method.__class__.__name__}: {str(e)}")


class AlertMethod:
    """Base class for alert methods"""
    def send_alert(self, alert_data):
        """Send an alert (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement send_alert()")

# Add to src/alerts/alert_system.py
class MongoDBAlertMethod(AlertMethod):
    """Alert method that saves to MongoDB"""
    def __init__(self, connection_string="mongodb://localhost:27017/", db_name="lolbins_ids"):
        try:
            from pymongo import MongoClient
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            
            # Test connection
            self.client.admin.command('ping')
            logging.info("MongoDB connection successful")
            
            self.db = self.client[db_name]
            self.alerts_collection = self.db["alerts"]
            
            # Create indexes for better querying
            self.alerts_collection.create_index("timestamp")
            self.alerts_collection.create_index("severity")
            self.alerts_collection.create_index("rule_name")
            self.alerts_collection.create_index("process_name")
            
            self.connection_ok = True
            logging.info("MongoDB alert method initialized successfully")
        except Exception as e:
            self.connection_ok = False
            logging.error(f"Error initializing MongoDB alert method: {str(e)}")
    
    def send_alert(self, alert_data):
        try:
            if not hasattr(self, 'connection_ok') or not self.connection_ok:
                logging.error("MongoDB connection not available")
                return False
                
            # Insert alert into MongoDB
            result = self.alerts_collection.insert_one(alert_data)
            logging.info(f"Alert saved to MongoDB with ID: {result.inserted_id}")
            return True
        except Exception as e:
            logging.error(f"Error writing alert to MongoDB: {str(e)}")
            return False
class ConsoleAlertMethod(AlertMethod):
    """Alert method that prints to console"""
    def send_alert(self, alert_data):
        severity = alert_data.get("severity", 0)
        rule_name = alert_data.get("rule_name", "Unknown Rule")
        process = alert_data.get("process_name", "Unknown Process")
        
        # Format the alert message with MITRE ATT&CK info if available
        mitre_info = ""
        if 'mitre_attack' in alert_data:
            attack = alert_data['mitre_attack']
            mitre_info = (
                f"MITRE ATT&CK:\n"
                f"Technique: {attack['technique_id']} - {attack['technique_name']}\n"
                f"Tactic: {attack['tactic']}\n"
                f"Reference: {attack['url']}\n"
            )
        
        alert_message = (
            f"\n{'='*60}\n"
            f"SECURITY ALERT - Severity: {severity}/5\n"
            f"Rule: {rule_name}\n"
            f"Process: {process} (PID: {alert_data.get('pid', 'Unknown')})\n"
            f"User: {alert_data.get('username', 'Unknown')}\n"
            f"Command: {alert_data.get('command_line', 'Unknown')}\n"
            f"Description: {alert_data.get('description', 'No description')}\n"
            f"Timestamp: {alert_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
            f"{mitre_info}"
            f"{'='*60}\n"
        )
        
        print(alert_message)
        return True


class FileAlertMethod(AlertMethod):
    """Alert method that saves to a JSON file"""
    def __init__(self, filename="alerts.json"):
        self.filename = filename
        
        # Initialize file if it doesn't exist
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                json.dump({"alerts": []}, f)
    
    def send_alert(self, alert_data):
        try:
            # Read existing alerts
            with open(self.filename, 'r') as f:
                data = json.load(f)
            
            # Add new alert
            if "alerts" not in data:
                data["alerts"] = []
                
            data["alerts"].append(alert_data)
            
            # Write back to file
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=2)
                
            return True
        except Exception as e:
            logging.error(f"Error writing alert to file: {str(e)}")
            return False


class EmailAlertMethod(AlertMethod):
    """Alert method that sends email notifications"""
    def __init__(self, server, port, username, password, recipients):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.recipients = recipients if isinstance(recipients, list) else [recipients]
    
    def send_alert(self, alert_data):
        if not self.recipients:
            logging.warning("No email recipients configured")
            return False
            
        severity = alert_data.get("severity", 0)
        rule_name = alert_data.get("rule_name", "Unknown Rule")
        
        # Create email
        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = ', '.join(self.recipients)
        msg['Subject'] = f"SECURITY ALERT - {rule_name} [Severity: {severity}/5]"
        
        # Format the alert message
        body = (
            f"<h2>SECURITY ALERT - Severity: {severity}/5</h2>"
            f"<p><strong>Rule:</strong> {rule_name}</p>"
            f"<p><strong>Process:</strong> {alert_data.get('process_name', 'Unknown')} "
            f"(PID: {alert_data.get('pid', 'Unknown')})</p>"
            f"<p><strong>User:</strong> {alert_data.get('username', 'Unknown')}</p>"
            f"<p><strong>Command:</strong> {alert_data.get('command_line', 'Unknown')}</p>"
            f"<p><strong>Description:</strong> {alert_data.get('description', 'No description')}</p>"
            f"<p><strong>Timestamp:</strong> {alert_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>"
        )
        
        msg.attach(MIMEText(body, 'html'))
        
        try:
            # Connect to server and send email
            server = smtplib.SMTP(self.server, self.port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            logging.error(f"Error sending email alert: {str(e)}")
            return False


# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test alert manager
    alert_manager = AlertManager()
    
    # Create a test alert
    test_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "Test Rule",
        'description': "This is a test alert",
        'severity': 4,
        'process_name': "test.exe",
        'command_line': "test.exe -malicious -args",
        'pid': 9999,
        'username': "test_user"
    }
    
    # Send the test alert
    alert_manager.send_alert(test_alert)
    
    print("Test alert sent. Check alerts.json for the saved alert.")