import time
import psutil
import logging
import json
import os
from datetime import datetime
from threading import Thread

class PerformanceMonitor:
    """Monitor system and IDS performance metrics"""
    
    def __init__(self, output_file="performance_stats.json"):
        self.output_file = output_file
        self.monitoring = False
        self.monitor_thread = None
        self.interval = 60  # Default: collect stats every 60 seconds
        self.stats = {
            "system": [],
            "ids": {
                "processes_analyzed": 0,
                "alerts_generated": 0,
                "rule_matches": {},
                "execution_times": []
            }
        }
        logging.info("Performance monitor initialized")
    
    def start_monitoring(self, interval=60):
        """Start monitoring in a background thread"""
        if self.monitoring:
            logging.warning("Performance monitoring already running")
            return
            
        self.interval = interval
        self.monitoring = True
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logging.info(f"Performance monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self._save_stats()
        logging.info("Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.monitoring:
            self._collect_system_stats()
            time.sleep(self.interval)
    
    def _collect_system_stats(self):
        """Collect system performance metrics"""
        stats = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage('/').percent,
            "network_io": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            }
        }
        
        self.stats["system"].append(stats)
        
        # Only keep the last 100 system stats to avoid memory growth
        if len(self.stats["system"]) > 100:
            self.stats["system"] = self.stats["system"][-100:]
            
        # Save periodically
        self._save_stats()
    
    def record_process_analysis(self, execution_time):
        """Record metrics about process analysis"""
        self.stats["ids"]["processes_analyzed"] += 1
        self.stats["ids"]["execution_times"].append(execution_time)
        
        # Only keep the last 1000 execution times
        if len(self.stats["ids"]["execution_times"]) > 1000:
            self.stats["ids"]["execution_times"] = self.stats["ids"]["execution_times"][-1000:]
    
    def record_alert(self, rule_name):
        """Record alert generation"""
        self.stats["ids"]["alerts_generated"] += 1
        
        if rule_name not in self.stats["ids"]["rule_matches"]:
            self.stats["ids"]["rule_matches"][rule_name] = 0
            
        self.stats["ids"]["rule_matches"][rule_name] += 1
    
    def get_performance_summary(self):
        """Get a summary of performance metrics"""
        if not self.stats["system"]:
            return {"status": "No data collected yet"}
            
        # Calculate averages from recent stats
        recent_stats = self.stats["system"][-10:]
        
        avg_cpu = sum(stat["cpu_percent"] for stat in recent_stats) / len(recent_stats)
        avg_memory = sum(stat["memory_percent"] for stat in recent_stats) / len(recent_stats)
        
        # Calculate IDS metrics
        if self.stats["ids"]["execution_times"]:
            avg_execution_time = sum(self.stats["ids"]["execution_times"]) / len(self.stats["ids"]["execution_times"])
        else:
            avg_execution_time = 0
            
        top_rules = sorted(
            self.stats["ids"]["rule_matches"].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        summary = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system": {
                "avg_cpu_percent": round(avg_cpu, 2),
                "avg_memory_percent": round(avg_memory, 2),
                "current_cpu_percent": recent_stats[-1]["cpu_percent"],
                "current_memory_percent": recent_stats[-1]["memory_percent"],
            },
            "ids": {
                "total_processes_analyzed": self.stats["ids"]["processes_analyzed"],
                "total_alerts_generated": self.stats["ids"]["alerts_generated"],
                "avg_execution_time_ms": round(avg_execution_time * 1000, 2),
                "top_triggered_rules": dict(top_rules)
            }
        }
        
        return summary
    
    def _save_stats(self):
        """Save performance stats to file"""
        try:
            # Create a summarized version for storage
            summary = self.get_performance_summary()
            
            with open(self.output_file, 'w') as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving performance stats: {str(e)}")

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test the performance monitor
    monitor = PerformanceMonitor()
    
    print("Starting performance monitoring for 10 seconds...")
    monitor.start_monitoring(interval=2)
    
    # Simulate some process analysis
    for i in range(5):
        time.sleep(1)
        # Simulate process analysis time (0.05 seconds)
        monitor.record_process_analysis(0.05)
        
        # Simulate some alerts
        if i % 2 == 0:
            monitor.record_alert("CertUtil Download")
        else:
            monitor.record_alert("PowerShell Encoded Command")
    
    # Wait a bit more to collect system stats
    time.sleep(5)
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    # Print performance summary
    summary = monitor.get_performance_summary()
    print(json.dumps(summary, indent=2))