# run_analysis.py
import sys
import os
import logging
import argparse
from datetime import datetime, timedelta

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.analysis.threat_analyzer import ThreatAnalyzer

def setup_logging():
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="LOLBin IDS Threat Analysis")
    parser.add_argument("--days", type=int, default=7, 
                      help="Analyze data from the past N days")
    parser.add_argument("--output", type=str, default="threat_report.json",
                      help="Output file for threat report")
    
    args = parser.parse_args()
    
    analyzer = ThreatAnalyzer()
    
    print(f"Analyzing threats from the past {args.days} days...")
    
    # Get attack patterns
    patterns = analyzer.get_attack_patterns(days=args.days)
    
    if patterns:
        print(f"Found {len(patterns)} potential attack patterns:")
        for i, pattern in enumerate(patterns, 1):
            print(f"\n{i}. User: {pattern['username']}")
            print(f"   Download: {pattern['download_process']['process_name']} - {pattern['download_process']['command_line']}")
            print(f"   Execution: {pattern['execution_process']['process_name']} - {pattern['execution_process']['command_line']}")
            print(f"   Time between: {pattern['time_between']:.2f} seconds")
    else:
        print("No suspicious attack patterns found.")
    
    # Save to JSON file
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump({
                "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "period_days": args.days,
                "patterns": patterns
            }, f, indent=2, default=str)
        
        print(f"\nThreat report saved to {args.output}")

if __name__ == "__main__":
    setup_logging()
    main()