import sys
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import the rule engine
from rules.enhanced_rule_engine import EnhancedRuleEngine

# Get the path to the rule_engine.py file
rule_engine_path = os.path.join(os.path.dirname(__file__), 'src', 'rules', 'enhanced_rule_engine.py')

def apply_patch():
    """Apply patch to fix the rule engine"""
    # Read the current file
    with open(rule_engine_path, 'r') as f:
        content = f.read()
    
    # Create backup
    backup_path = rule_engine_path + '.bak'
    with open(backup_path, 'w') as f:
        f.write(content)
    print(f"Backup created at {backup_path}")
    
    # Define the replacement analyze_process method
    new_method = """    def analyze_process(self, process_info):
        \"\"\"
        Analyze a process against enhanced detection rules
        
        Args:
            process_info (dict): Process information from process monitor
            
        Returns:
            list: List of triggered rules and their details
        \"\"\"
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
        for current_rule in self.rules:
            if process_name == current_rule.lolbin:
                # Check if command matches the suspicious pattern
                if current_rule.pattern.search(cmdline):
                    # Check for whitelist patterns
                    whitelisted = False
                    for whitelist_pattern in current_rule.whitelist_patterns:
                        if whitelist_pattern.search(cmdline):
                            logging.debug(f"Command matches whitelist pattern: {whitelist_pattern.pattern}")
                            whitelisted = True
                            break
                    
                    if whitelisted:
                        continue
                    
                    # Check for required arguments
                    if current_rule.required_args:
                        required_args_present = all(arg in cmdline for arg in current_rule.required_args)
                        if not required_args_present:
                            continue
                    
                    # Check for required context
                    if current_rule.context_required:
                        # Get the process history for this user
                        user_history = self.process_history[username]
                        context_match = any(ctx_proc in user_history for ctx_proc in current_rule.context_required)
                        
                        if not context_match and current_rule.context_required:
                            # Lower severity if context is not fully matched
                            adjusted_severity = max(1, current_rule.severity - 2)
                            logging.debug(f"Context not fully matched. Severity adjusted from {current_rule.severity} to {adjusted_severity}")
                        else:
                            adjusted_severity = current_rule.severity
                    else:
                        adjusted_severity = current_rule.severity
                    
                    # Create alert
                    alert = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'rule_name': current_rule.name,
                        'description': current_rule.description,
                        'severity': adjusted_severity,
                        'process_name': process_name,
                        'command_line': cmdline,
                        'pid': process_info.get('pid'),
                        'username': username,
                        'context': list(self.process_history[username])
                    }
                    
                    logging.warning(f"Rule triggered: {current_rule.name} (Severity: {adjusted_severity})")
                    results.append(alert)
        
        return results"""
    
    # Find and replace the analyze_process method
    import re
    pattern = r'def analyze_process\(self, process_info\):.*?return results'
    replacement = new_method
    
    # Use re.DOTALL to match across multiple lines
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    # Write the updated content
    with open(rule_engine_path, 'w') as f:
        f.write(new_content)
    
    print(f"Rule engine patched successfully")

if __name__ == "__main__":
    apply_patch()