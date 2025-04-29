import subprocess
import os
import time
import threading
import tkinter as tk
from tkinter import messagebox
import webbrowser
import win32serviceutil

PYTHON_EXE = "C:/Users/asus/AppData/Local/Programs/Python/Python313/python.exe"
SERVICE_NAME = "LolbinIdsMonitor"
BASE_DIR = os.path.join(os.path.dirname(__file__), "src")

def install_service_if_needed():
    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' already installed.")
    except Exception:
        print(f"[+] Service '{SERVICE_NAME}' not found. Installing now...")
        # Use the install_service.py from the root directory
        root_dir = os.path.dirname(BASE_DIR)
        subprocess.run([PYTHON_EXE, "install_service.py", "install"], cwd=root_dir)

def start_monitoring_service():
    print("[+] Starting Monitoring Service (LolbinIdsMonitor)...")
    # Use the install_service.py from the root directory
    root_dir = os.path.dirname(BASE_DIR)
    subprocess.run([PYTHON_EXE, "install_service.py", "start"], cwd=root_dir)

def start_dashboard():
    print("[+] Starting Dashboard (Flask App)...")
    dashboard_dir = os.path.join(BASE_DIR, "dashboard")
    subprocess.Popen([PYTHON_EXE, "app.py"], cwd=dashboard_dir)

def start_notification_orchestrator():
    print("[+] Starting Notification Orchestrator (Tkinter popups)...")
    subprocess.Popen([PYTHON_EXE, "-m", "notification.notification_orchestrator"], cwd=BASE_DIR)

def show_startup_popup_and_open_browser():
    time.sleep(3)
    webbrowser.open("http://localhost:5000")
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Monitoring Started",
        "Monitoring service has started successfully!\n\nVisit:\nhttp://localhost:5000\n\nto access your Dashboard."
    )
    root.destroy()

def main():
    print("[+] Initializing all components...")

    install_service_if_needed()
    time.sleep(2)

    start_monitoring_service()
    time.sleep(2)

    start_dashboard()
    threading.Thread(target=show_startup_popup_and_open_browser, daemon=True).start()
    time.sleep(8)

    start_notification_orchestrator()

    print("[+] All services started successfully!")
    print("[+] Dashboard available at: http://localhost:5000")
    print("[+] Monitoring and Notifications running in background.")
    print("[*] Keep this terminal open to keep everything running!")

if __name__ == "__main__":
    main()
