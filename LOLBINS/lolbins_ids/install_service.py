import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from src.service.lolbin_monitor_service import LolbinMonitorService
import win32serviceutil

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("[ERROR] This script must be run with arguments: install, start, stop, remove")
    else:
        win32serviceutil.HandleCommandLine(LolbinMonitorService)
