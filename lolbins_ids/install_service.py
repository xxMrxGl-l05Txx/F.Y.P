import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from src.service.lolbin_monitor_service import LolbinMonitorService
import win32serviceutil
# Define service configuration
class LolbinMonitorServiceConfig:
    _svc_name_ = "LolbinMonitorService"
    _svc_display_name_ = "Lolbin Monitor Service"
    _svc_description_ = "Monitors system for Living-off-the-Land binary executions"

# Apply configuration to service class
for attr_name, attr_value in vars(LolbinMonitorServiceConfig).items():
    if not attr_name.startswith('__'):
        setattr(LolbinMonitorService, attr_name, attr_value)
if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("[ERROR] This script must be run with arguments: install, start, stop, remove")
    else:
        win32serviceutil.HandleCommandLine(LolbinMonitorService)
