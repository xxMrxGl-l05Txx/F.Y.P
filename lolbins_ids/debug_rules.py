import sys
import os
import logging
import re

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import the rule engine
from rules.enhanced_rule_engine import EnhancedRuleEngine

def debug_rule_matching():
    """Debug rule matching for PowerShell encoded commands"""
    # Initialize rule engine
    rule_engine = EnhancedRuleEngine()
    
    # List all rules
    print("Registered rules:")
    for idx, rule in enumerate(rule_engine.rules, 1):
        print(f"{idx}. {rule.name} (LOLBin: {rule.lolbin}, Pattern: {rule.pattern.pattern})")
    
    # Test process
    test_process = {
        'name': 'powershell.exe',
        'cmdline': ['powershell.exe', '-e', 'ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA='],
        'pid': 1234,
        'username': 'DESKTOP\\Administrator'
    }
    
    # Manual pattern matching
    print("\nTesting pattern matching manually:")
    cmdline = ' '.join(test_process['cmdline'])
    print(f"Command line: {cmdline}")
    
    for rule in rule_engine.rules:
        if rule.lolbin == test_process['name'].lower():
            print(f"Testing rule: {rule.name}")
            match = rule.pattern.search(cmdline)
            print(f"  - Pattern match: {bool(match)}")
            if match:
                print(f"  - Match groups: {match.groups()}")
    
    # Test full analysis
    print("\nTesting full rule engine analysis:")
    alerts = rule_engine.analyze_process(test_process)
    print(f"Generated {len(alerts)} alerts")
    for alert in alerts:
        print(f"Alert: {alert['rule_name']} (Severity: {alert['severity']})")

if __name__ == "__main__":
    debug_rule_matching()