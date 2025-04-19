# email_provider.py
# Provider for email notifications

import os
import logging
import smtplib
import ssl
import socket
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from datetime import datetime

class EmailProvider:
    """Provider for sending email notifications"""
    
    def __init__(self, config):
        """
        Initialize the email notification provider
        
        Args:
            config (dict): Configuration options
        """
        self.config = config
        self.smtp_server = config.get('smtp_server', '')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('smtp_username', '')
        self.password = config.get('smtp_password', '')
        self.from_address = config.get('from_address', 'lolbins-ids-alerts@example.com')
        self.recipients = config.get('recipients', [])
        self.use_ssl = config.get('use_ssl', False)
        self.use_tls = config.get('use_tls', True)
        
        # Templates directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(os.path.dirname(script_dir), 'templates')
        self.template_dir = config.get('template_dir', template_dir)
        
        # Load HTML template
        self.html_template = self._load_template('email_alert.html')
        if not self.html_template:
            self.html_template = self._get_default_html_template()
            
        # Load plain text template
        self.text_template = self._load_template('email_alert.txt')
        if not self.text_template:
            self.text_template = self._get_default_text_template()
        
        # Validate configuration
        if not self.smtp_server or not self.recipients:
            logging.warning("Email provider missing required configuration (SMTP server or recipients)")
    
    def _load_template(self, template_name):
        """Load a template file"""
        template_path = os.path.join(self.template_dir, template_name)
        if os.path.exists(template_path):
            try:
                with open(template_path, 'r') as f:
                    return f.read()
            except Exception as e:
                logging.error(f"Error loading template {template_name}: {str(e)}")
        return None
    
    def _get_default_html_template(self):
        """Get the default HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>LOLBins IDS Security Alert</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
                .container { max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 5px; }
                .header { background-color: #{{header_color}}; color: white; padding: 10px 20px; border-radius: 5px 5px 0 0; }
                .header h1 { margin: 0; font-size: 22px; }
                .content { padding: 20px; }
                .alert-info { margin-bottom: 20px; }
                .alert-info h2 { font-size: 18px; margin-top: 0; color: #{{header_color}}; }
                .alert-detail { margin-bottom: 15px; }
                .label { font-weight: bold; min-width: 120px; display: inline-block; }
                .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }
                .command { background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; margin-top: 5px; }
                .footer { background-color: #f5f5f5; padding: 10px 20px; border-top: 1px solid #ddd; font-size: 12px; color: #777; border-radius: 0 0 5px 5px; }
                .correlation { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin-top: 15px; }
                .correlation.critical { background-color: #f8d7da; border-left: 4px solid #dc3545; }
                .mitre { margin-top: 15px; background-color: #f8f9fa; padding: 10px; border-left: 4px solid #6c757d; }
                .alert-time { color: #777; font-style: italic; font-size: 14px; margin-top: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{{title}}</h1>
                </div>
                <div class="content">
                    <div class="alert-info">
                        <h2>{{rule_name}}</h2>
                        <div class="alert-time">Detected at {{timestamp}}</div>
                        <p>{{description}}</p>
                        
                        <div class="alert-detail">
                            <span class="label">Severity:</span>
                            <span class="severity" style="background-color: {{severity_color}};">{{severity}}</span>
                        </div>
                        
                        <div class="alert-detail">
                            <span class="label">Process:</span> {{process_name}} (PID: {{pid}})
                        </div>
                        
                        <div class="alert-detail">
                            <span class="label">User:</span> {{username}}
                        </div>
                        
                        <div class="alert-detail">
                            <span class="label">Command:</span>
                            <div class="command">{{command_line}}</div>
                        </div>
                        
                        {{#correlation}}
                        <div class="correlation {{#attack_chain_complete}}critical{{/attack_chain_complete}}">
                            <strong>{{#attack_chain_complete}}ATTACK CHAIN DETECTED{{/attack_chain_complete}}{{^attack_chain_complete}}Part of potential attack chain{{/attack_chain_complete}}:</strong> {{rule_name}}<br>
                            {{#related_alerts}}
                            <div style="margin-top: 5px;">Related alerts: {{related_alerts}}</div>
                            {{/related_alerts}}
                        </div>
                        {{/correlation}}
                        
                        {{#mitre_attack}}
                        <div class="mitre">
                            <strong>MITRE ATT&CK:</strong><br>
                            Technique: {{technique_id}} - {{technique_name}}<br>
                            Tactic: {{tactic}}<br>
                            <a href="{{url}}">View in MITRE ATT&CK Framework</a>
                        </div>
                        {{/mitre_attack}}
                    </div>
                    
                    <p>Please investigate this alert promptly.</p>
                </div>
                <div class="footer">
                    This is an automated security alert from LOLBins IDS. Do not reply to this email.
                </div>
            </div>
        </body>
        </html>
        """
    
    def _get_default_text_template(self):
        """Get the default plain text template"""
        return """
        LOLBins IDS Security Alert: {{title}}
        =================================================================
        
        ALERT: {{rule_name}}
        Detected at: {{timestamp}}
        
        {{description}}
        
        Severity: {{severity}} ({{severity_text}})
        Process: {{process_name}} (PID: {{pid}})
        User: {{username}}
        
        Command:
        {{command_line}}
        
        {% if correlation %}
        {% if attack_chain_complete %}
        !!! ATTACK CHAIN DETECTED: {{correlation.rule_name}} !!!
        {% else %}
        Part of potential attack chain: {{correlation.rule_name}}
        {% endif %}
        
        {% if related_alerts %}
        Related alerts: {{related_alerts}}
        {% endif %}
        {% endif %}
        
        {% if mitre_attack %}
        MITRE ATT&CK:
        Technique: {{mitre_attack.technique_id}} - {{mitre_attack.technique_name}}
        Tactic: {{mitre_attack.tactic}}
        Reference: {{mitre_attack.url}}
        {% endif %}
        
        =================================================================
        Please investigate this alert promptly.
        
        This is an automated security alert from LOLBins IDS. Do not reply to this email.
        """
    
    def send_notification(self, alert):
        """
        Send an email notification
        
        Args:
            alert (dict): The alert data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.smtp_server or not self.recipients:
            logging.warning("Email notification failed: Missing configuration")
            return False
        
        try:
            # Create message
            msg = self._create_email_message(alert)
            
            # Send email
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            
            # Use TLS if configured
            if self.use_tls and not self.use_ssl:
                server.starttls()
            
            # Login if credentials provided
            if self.username and self.password:
                server.login(self.username, self.password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent to {', '.join(self.recipients)}")
            return True
            
        except Exception as e:
            logging.error(f"Error sending email notification: {str(e)}")
            return False
    
    def _create_email_message(self, alert):
        """
        Create the email message for the alert
        
        Args:
            alert (dict): The alert data
            
        Returns:
            MIMEMultipart: The email message
        """
        # Get alert data with defaults
        severity = alert.get('severity', 1)
        rule_name = alert.get('rule_name', 'Unknown Rule')
        process_name = alert.get('process_name', 'Unknown Process')
        description = alert.get('description', 'No description')
        timestamp = alert.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pid = alert.get('pid', 'Unknown')
        username = alert.get('username', 'Unknown')
        command_line = alert.get('command_line', '')
        correlation = alert.get('correlation', {})
        mitre_attack = alert.get('mitre_attack', {})
        hostname = socket.gethostname()
        
        # Determine severity text and colors
        severity_text = self._get_severity_text(severity)
        severity_color = self._get_severity_color(severity)
        header_color = severity_color
        
        # Determine title based on severity
        if severity >= 5:
            title_prefix = "CRITICAL SECURITY ALERT"
        elif severity >= 4:
            title_prefix = "HIGH SEVERITY SECURITY ALERT"
        elif severity >= 3:
            title_prefix = "MEDIUM SECURITY ALERT"
        else:
            title_prefix = "SECURITY ALERT"
        
        title = f"{title_prefix}: {rule_name}"
        
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[{severity_text.upper()}] LOLBins IDS Alert - {rule_name} on {hostname}"
        msg['From'] = self.from_address
        msg['To'] = ", ".join(self.recipients)
        msg['Date'] = formatdate(localtime=True)
        
        # Create template context
        context = {
            'title': title,
            'rule_name': rule_name,
            'description': description,
            'severity': severity,
            'severity_text': severity_text,
            'severity_color': severity_color,
            'header_color': header_color,
            'process_name': process_name,
            'pid': pid,
            'username': username,
            'command_line': command_line,
            'timestamp': timestamp,
            'hostname': hostname
        }
        
        # Add correlation info if present
        if correlation and correlation.get('is_correlated', False):
            context['correlation'] = correlation
            
            if 'related_alerts' in correlation:
                context['related_alerts'] = ", ".join(correlation['related_alerts'])
        
        # Add MITRE ATT&CK info if present
        if mitre_attack:
            context['mitre_attack'] = mitre_attack
        
        # Create plain text and HTML parts
        text_content = self._render_template(self.text_template, context)
        html_content = self._render_template(self.html_template, context)
        
        # Attach parts
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        return msg
    
    def _render_template(self, template, context):
        """
        Render a template with the given context
        
        Args:
            template (str): The template string
            context (dict): The context variables
            
        Returns:
            str: The rendered template
        """
        # This is a simple template renderer, in production you might want to use a proper
        # template engine like Jinja2, but we're keeping dependencies minimal
        
        result = template
        
        # Replace simple variables
        for key, value in context.items():
            if isinstance(value, (str, int, float)):
                result = result.replace('{{' + key + '}}', str(value))
        
        # Handle conditionals - very basic implementation
        # Handle correlation section
        if 'correlation' in context and context['correlation'].get('is_correlated', False):
            result = result.replace('{{#correlation}}', '')
            result = result.replace('{{/correlation}}', '')
            
            if context['correlation'].get('attack_chain_complete', False):
                result = result.replace('{{#attack_chain_complete}}', '')
                result = result.replace('{{/attack_chain_complete}}', '')
                result = result.replace('{{^attack_chain_complete}}', '<!-- ')
                result = result.replace('{{/attack_chain_complete}}', ' -->')
            else:
                result = result.replace('{{#attack_chain_complete}}', '<!-- ')
                result = result.replace('{{/attack_chain_complete}}', ' -->')
                result = result.replace('{{^attack_chain_complete}}', '')
                result = result.replace('{{/attack_chain_complete}}', '')
            
            # Handle related alerts section 
            if 'related_alerts' in context:
                result = result.replace('{{#related_alerts}}', '')
                result = result.replace('{{/related_alerts}}', '')
        else:
            # Remove the whole correlation section if not correlated
            import re
            result = re.sub(r'{{#correlation}}.*?{{/correlation}}', '', result, flags=re.DOTALL)
        
        # Handle MITRE ATT&CK section
        if 'mitre_attack' in context:
            result = result.replace('{{#mitre_attack}}', '')
            result = result.replace('{{/mitre_attack}}', '')
        else:
            # Remove the whole MITRE section if not present
            import re
            result = re.sub(r'{{#mitre_attack}}.*?{{/mitre_attack}}', '', result, flags=re.DOTALL)
        
        return result
    
    def _get_severity_text(self, severity):
        """Get text representation of severity level"""
        if severity >= 5:
            return "Critical"
        elif severity == 4:
            return "High"
        elif severity == 3:
            return "Medium"
        elif severity == 2:
            return "Medium-Low"
        else:
            return "Low"
    
    def _get_severity_color(self, severity):
        """Get color representation of severity level"""
        if severity >= 5:
            return "#dc3545"  # Bootstrap danger
        elif severity == 4:
            return "#fd7e14"  # Bootstrap warning-dark
        elif severity == 3:
            return "#ffc107"  # Bootstrap warning
        elif severity == 2:
            return "#17a2b8"  # Bootstrap info
        else:
            return "#28a745"  # Bootstrap success

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test configuration
    test_config = {
        "enabled": True,
        "min_severity": 3,
        "smtp_server": "localhost",  # For testing, use a local SMTP debugging server
        "smtp_port": 1025,           # For testing with MailHog or similar tool
        "from_address": "lolbins-ids@example.com",
        "recipients": ["security-team@example.com"]
    }
    
    # Create provider
    provider = EmailProvider(test_config)
    
    # Create a test alert
    test_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "PowerShell Encoded Command",
        'description': "PowerShell executing encoded commands",
        'severity': 4,
        'process_name': "powershell.exe",
        'command_line': "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
        'pid': 1234,
        'username': "test_user",
        'mitre_attack': {
            'technique_id': "T1059.001",
            'technique_name': "Command and Scripting Interpreter: PowerShell",
            'tactic': "Execution",
            'url': "https://attack.mitre.org/techniques/T1059/001/"
        }
    }
    
    # Add correlation for testing
    test_alert['correlation'] = {
        'is_correlated': True,
        'group_id': "Download_And_Execute-test_user-20230101000000",
        'rule_name': "Download and Execute Chain",
        'chain_position': 2,
        'related_alerts': ['CertUtil Download'],
        'attack_chain_length': 2,
        'attack_chain_complete': True
    }
    
    # Send notification
    print("Sending test email...")
    result = provider.send_notification(test_alert)
    print(f"Email sent: {result}")
    
    # Note: For testing, you can use MailHog:
    # 1. Install MailHog from https://github.com/mailhog/MailHog
    # 2. Run MailHog
    # 3. Execute this script
    # 4. Open http://localhost:8025 to view the email