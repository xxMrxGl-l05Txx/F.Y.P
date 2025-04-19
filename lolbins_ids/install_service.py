import os
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from service.lolbin_monitor_service import LolbinMonitorService

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(LolbinMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(LolbinMonitorService)