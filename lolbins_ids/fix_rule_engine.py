import os
import sys

# Get the path to the rule_engine.py file
rule_engine_path = os.path.join(os.path.dirname(__file__), 'src', 'rules', 'enhanced_rule_engine.py')

# Create backup if it doesn't exist yet
backup_path = rule_engine_path + '.bak'
if not os.path.exists(backup_path):
    with open(rule_engine_path, 'r') as original:
        with open(backup_path, 'w') as backup:
            backup.write(original.read())
    print(f"Backup created at {backup_path}")

# Open the file and locate the analyze_process method
with open(rule_engine_path, 'r') as f:
    lines = f.readlines()

# Prepare new content
new_content = []
skip_mode = False
for line in lines:
    # Check if we're at the beginning of the analyze_process method
    if line.strip().startswith('def analyze_process(self, process_info):'):
        # Add the function definition
        new_content.append(line)
        # Enter skip mode to skip the old function body
        skip_mode = True
        # Add the corrected implementation with proper indentation
        new_content.append('''        """
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
        
        return results
''')
    elif skip_mode:
        # If we're in skip mode, check if we've reached the end of the method
        if line.strip() == "return results":
            skip_mode = False
    elif not skip_mode:
        # If we're not in skip mode, add the line to the new content
        new_content.append(line)

# Write the updated content back to the file
with open(rule_engine_path, 'w') as f:
    f.writelines(new_content)

print("Rule engine fixed successfully!")