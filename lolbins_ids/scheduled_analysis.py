# scheduled_analysis.py
import sys
import os
import logging
import time
import json
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.analysis.threat_analyzer import ThreatAnalyzer
from src.database.connection import DatabaseConnection

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='analysis.log'
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger('').addHandler(console)

def run_analysis():
    """Run a complete threat analysis and store results"""
    analyzer = ThreatAnalyzer()
    connection = DatabaseConnection.get_instance()
    db = connection.db
    
    logging.info("Starting scheduled threat analysis...")
    
    # Run all analyses
    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_patterns": analyzer.get_attack_patterns(),
        "high_risk_users": analyzer.get_high_risk_users(),
        "lolbin_usage": analyzer.get_common_lolbin_usage(),
        "mitre_summary": analyzer.get_mitre_attack_summary()
    }
    
    # Store results in MongoDB
    try:
        db.analysis_reports.insert_one(results)
        logging.info("Analysis results stored in database")
    except Exception as e:
        logging.error(f"Error storing analysis results: {str(e)}")
    
    # Check for critical findings that need immediate attention
    if results["attack_patterns"] or any(user["max_severity"] == 5 for user in results["high_risk_users"]):
        logging.warning("CRITICAL FINDINGS: High severity threats detected!")
        
        # Here you could add notification code for critical findings
        # For example, sending an email or SMS alert
    
    logging.info("Analysis complete")

if __name__ == "__main__":
    setup_logging()
    
    # Run once immediately
    run_analysis()
    
    # Or run on a schedule
    # while True:
    #     run_analysis()
    #     # Run every 6 hours
    #     time.sleep(6 * 60 * 60)