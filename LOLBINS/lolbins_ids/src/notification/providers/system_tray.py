# system_tray.py
# Provider for Windows system tray notifications

import os
import sys
import logging
import threading
import queue
import socket
import json
import time
import tempfile
from datetime import datetime
from pathlib import Path

# Import Windows-specific modules
try:
    import win32api
    import win32con
    import win32gui
    import winreg
    from win32com.client import Dispatch
    from win32gui import NIF_ICON, NIF_MESSAGE, NIF_TIP, NIIF_WARNING, NIIF_ERROR, NIIF_INFO
except ImportError:
    logging.error("Windows dependencies not found. Install with: pip install pywin32")
    raise

# For tray icon
try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    logging.error("pystray and/or PIL not found. Install with: pip install pystray pillow")
    raise

# For toast notifications
try:
    from win10toast_click import ToastNotifier
except ImportError:
    logging.error("win10toast_click not found. Install with: pip install win10toast-click")
    raise

class SystemTrayProvider:
    """Provider for Windows system tray notifications with toast alerts"""
    
    def __init__(self, config):
        """
        Initialize the system tray notification provider
        
        Args:
            config (dict): Configuration options
        """
        self.config = config
        self.notification_queue = queue.Queue()
        self.recent_alerts = []
        self.max_recent = config.get('max_recent_alerts', 10)
        self.icon = None
        self.notification_thread = None
        self.running = False
        self.toast = ToastNotifier()
        self.alert_log_path = self._get_alert_log_path()
        
        # Set up notification socket for receiving alerts from service
        self.setup_notification_socket()
        
        # Start the tray icon
        self.start_tray_icon()
    
    def _get_alert_log_path(self):
        """Get the path for the alert log file"""
        app_data = os.path.join(os.environ.get('APPDATA', tempfile.gettempdir()), 'LolbinIDS')
        os.makedirs(app_data, exist_ok=True)
        return os.path.join(app_data, 'recent_alerts.json')
    
    def _load_recent_alerts(self):
        """Load recent alerts from disk"""
        if os.path.exists(self.alert_log_path):
            try:
                with open(self.alert_log_path, 'r') as f:
                    self.recent_alerts = json.load(f)
                    # Keep only the most recent alerts
                    self.recent_alerts = self.recent_alerts[-self.max_recent:]
            except Exception as e:
                logging.error(f"Error loading recent alerts: {str(e)}")
                self.recent_alerts = []
    
    def _save_recent_alerts(self):
        """Save recent alerts to disk"""
        try:
            with open(self.alert_log_path, 'w') as f:
                json.dump(self.recent_alerts, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving recent alerts: {str(e)}")
    
    def setup_notification_socket(self):
        """Set up a socket to receive notifications from the service"""
        self.socket_thread = threading.Thread(target=self._socket_listener)
        self.socket_thread.daemon = True
        self.socket_thread.start()
    
    def _socket_listener(self):
        """Socket listener thread to receive alerts from service"""
        socket_path = r'\\.\pipe\lolbins_notification'
        
        try:
            import win32pipe
            import win32file
            
            while True:
                try:
                    # Create named pipe server
                    pipe = win32pipe.CreateNamedPipe(
                        socket_path,
                        win32pipe.PIPE_ACCESS_DUPLEX,
                        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                        1, 65536, 65536, 0, None
                    )
                    
                    # Wait for client connection
                    win32pipe.ConnectNamedPipe(pipe, None)
                    
                    # Read message
                    result, data = win32file.ReadFile(pipe, 65536)
                    message = data.decode('utf-8')
                    
                    # Process notification
                    try:
                        alert = json.loads(message)
                        self.notification_queue.put(alert)
                    except json.JSONDecodeError:
                        logging.error(f"Invalid JSON in notification: {message}")
                    
                    # Close pipe
                    win32file.CloseHandle(pipe)
                
                except Exception as e:
                    logging.error(f"Error in notification socket: {str(e)}")
                    time.sleep(1)  # Avoid tight loop on error
                    
        except Exception as e:
            logging.error(f"Critical error in socket listener: {str(e)}")
    
    def start_tray_icon(self):
        """Start the system tray icon in a separate thread"""
        self.icon_thread = threading.Thread(target=self._run_tray_icon)
        self.icon_thread.daemon = True
        self.icon_thread.start()
        
        # Also start notification processing
        self.running = True
        self.notification_thread = threading.Thread(target=self._process_notifications)
        self.notification_thread.daemon = True
        self.notification_thread.start()
    
    def _create_icon_image(self):
        """Create an icon image for the system tray"""
        width = 64
        height = 64
        color1 = (0, 120, 212)  # Primary color
        color2 = (255, 255, 255)  # Secondary color
        
        image = Image.new('RGB', (width, height), color=(0, 0, 0, 0))
        dc = ImageDraw.Draw(image)
        
        # Draw a shield icon
        dc.rectangle([(10, 10), (width-10, height-10)], outline=color2, width=2)
        dc.polygon([(width//2, 15), (width-15, height//3), (width-15, height-15), 
                   (width//2, height-15), (15, height-15), (15, height//3)], 
                   fill=color1, outline=color2)
        dc.text((width//2-5, height//2-5), "IDS", fill=color2)
        
        return image
    
    def _run_tray_icon(self):
        """Run the system tray icon"""
        try:
            # Create icon image
            icon_image = self._create_icon_image()
            
            # Create menu items
            def open_dashboard():
                """Open the web dashboard"""
                import webbrowser
                webbrowser.open("http://localhost:5000")
            
            def view_alerts():
                """View recent alerts"""
                self._show_alerts_window()
            
            def exit_app():
                """Exit the tray application"""
                icon.stop()
                self.running = False
            
            # Create the icon
            icon = pystray.Icon("lolbins_ids")
            icon.title = "LOLBins IDS Monitor"
            icon.icon = icon_image
            icon.menu = pystray.Menu(
                pystray.MenuItem("LOLBins IDS Monitor", None, enabled=False),
                pystray.MenuItem("Open Dashboard", open_dashboard),
                pystray.MenuItem("View Recent Alerts", view_alerts),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", exit_app)
            )
            
            # Save icon reference
            self.icon = icon
            
            # Run the icon
            icon.run()
        
        except Exception as e:
            logging.error(f"Error running system tray icon: {str(e)}")
    
    def _process_notifications(self):
        """Process notifications from the queue"""
        # Load recent alerts first
        self._load_recent_alerts()
        
        while self.running:
            try:
                # Get notification from queue with timeout
                try:
                    alert = self.notification_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process the notification
                self._show_notification(alert)
                
                # Add to recent alerts
                self.recent_alerts.append(alert)
                if len(self.recent_alerts) > self.max_recent:
                    self.recent_alerts.pop(0)
                
                # Save recent alerts
                self._save_recent_alerts()
                
                # Mark as done
                self.notification_queue.task_done()
                
            except Exception as e:
                logging.error(f"Error processing notification: {str(e)}")
    
    def _show_notification(self, alert):
        """
        Show a Windows toast notification
        
        Args:
            alert (dict): The alert data
        """
        severity = alert.get('severity', 1)
        rule_name = alert.get('rule_name', 'Unknown Rule')
        process = alert.get('process_name', 'Unknown Process')
        description = alert.get('description', 'No description')
        
        # Format title based on severity
        if severity >= 5:
            title_prefix = "CRITICAL ALERT"
        elif severity >= 4:
            title_prefix = "HIGH SEVERITY ALERT"
        elif severity >= 3:
            title_prefix = "MEDIUM ALERT"
        else:
            title_prefix = "ALERT"
        
        title = f"{title_prefix}: {rule_name}"
        
        # Format message
        message = f"Process: {process}\n{description}"
        
        # Add correlation info if present
        if alert.get('correlation', {}).get('is_correlated', False):
            chain_info = alert['correlation']
            if chain_info.get('attack_chain_complete', False):
                message += f"\n\nATTACK CHAIN DETECTED: {chain_info.get('rule_name', 'Unknown Attack Chain')}"
        
        # Define callback to open dashboard
        def open_dashboard():
            import webbrowser
            webbrowser.open("http://localhost:5000/alerts")
        
        # Show the notification
        try:
            self.toast.show_toast(
                title=title,
                msg=message,
                icon_path=None,  # None for default app icon
                duration=5,  # Show for 5 seconds
                threaded=True,
                callback_on_click=open_dashboard
            )
        except Exception as e:
            logging.error(f"Error showing toast notification: {str(e)}")
    
    def _show_alerts_window(self):
        """Show a window with recent alerts"""
        try:
            import tkinter as tk
            from tkinter import ttk
            
            root = tk.Tk()
            root.title("LOLBins IDS - Recent Alerts")
            root.geometry("800x600")
            root.minsize(600, 400)
            
            # Style
            style = ttk.Style()
            style.theme_use('clam')  # Use a theme that works well on Windows
            
            # Configure severity tag colors
            style.configure("Severity.5.TLabel", foreground="red", font=("TkDefaultFont", 10, "bold"))
            style.configure("Severity.4.TLabel", foreground="orange", font=("TkDefaultFont", 10, "bold"))
            style.configure("Severity.3.TLabel", foreground="gold", font=("TkDefaultFont", 10, "bold"))
            style.configure("Severity.2.TLabel", foreground="green", font=("TkDefaultFont", 10, "bold"))
            style.configure("Severity.1.TLabel", foreground="blue", font=("TkDefaultFont", 10, "bold"))
            
            # Create header
            header_frame = ttk.Frame(root, padding=10)
            header_frame.pack(fill=tk.X)
            
            ttk.Label(header_frame, text="Recent Security Alerts", font=("TkDefaultFont", 14, "bold")).pack(side=tk.LEFT)
            
            # Create scrollable frame for alerts
            container = ttk.Frame(root)
            container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            canvas = tk.Canvas(container)
            scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add alerts
            if not self.recent_alerts:
                ttk.Label(scrollable_frame, text="No recent alerts", font=("TkDefaultFont", 12, "italic")).pack(pady=20)
            else:
                # Sort alerts by timestamp (most recent first)
                sorted_alerts = sorted(
                    self.recent_alerts, 
                    key=lambda x: datetime.strptime(x.get('timestamp', '2000-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S"),
                    reverse=True
                )
                
                for alert in sorted_alerts:
                    # Create alert frame
                    alert_frame = ttk.Frame(scrollable_frame, padding=10)
                    alert_frame.pack(fill=tk.X, pady=5)
                    
                    # Add thin border around each alert
                    border_frame = ttk.Frame(alert_frame, relief="solid", borderwidth=1)
                    border_frame.pack(fill=tk.X, expand=True, pady=2)
                    
                    inner_frame = ttk.Frame(border_frame, padding=8)
                    inner_frame.pack(fill=tk.X, expand=True)
                    
                    # Header row with severity and rule name
                    header_row = ttk.Frame(inner_frame)
                    header_row.pack(fill=tk.X, pady=(0, 5))
                    
                    severity = alert.get('severity', 1)
                    severity_label = ttk.Label(
                        header_row, 
                        text=f"Severity {severity}",
                        style=f"Severity.{severity}.TLabel"
                    )
                    severity_label.pack(side=tk.LEFT)
                    
                    timestamp = alert.get('timestamp', 'Unknown time')
                    time_label = ttk.Label(header_row, text=timestamp)
                    time_label.pack(side=tk.RIGHT)
                    
                    # Rule name
                    rule_name = alert.get('rule_name', 'Unknown Rule')
                    rule_label = ttk.Label(inner_frame, text=rule_name, font=("TkDefaultFont", 12, "bold"))
                    rule_label.pack(fill=tk.X, pady=(0, 5))
                    
                    # Process info
                    process_frame = ttk.Frame(inner_frame)
                    process_frame.pack(fill=tk.X)
                    
                    process_name = alert.get('process_name', 'Unknown Process')
                    process_label = ttk.Label(process_frame, text=f"Process: {process_name}")
                    process_label.pack(side=tk.LEFT, padx=(0, 10))
                    
                    username = alert.get('username', 'Unknown User')
                    user_label = ttk.Label(process_frame, text=f"User: {username}")
                    user_label.pack(side=tk.LEFT)
                    
                    # Description
                    description = alert.get('description', 'No description')
                    desc_label = ttk.Label(inner_frame, text=description, wraplength=700)
                    desc_label.pack(fill=tk.X, pady=(5, 0))
                    
                    # Command line (if present)
                    cmd_line = alert.get('command_line', '')
                    if cmd_line:
                        cmd_frame = ttk.Frame(inner_frame)
                        cmd_frame.pack(fill=tk.X, pady=(5, 0))
                        
                        cmd_label = ttk.Label(cmd_frame, text="Command: ", font=("TkDefaultFont", 9, "bold"))
                        cmd_label.pack(side=tk.LEFT, anchor="n")
                        
                        cmd_text = ttk.Label(cmd_frame, text=cmd_line, wraplength=650, font=("Consolas", 9))
                        cmd_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
                    
                    # Correlation info (if present)
                    if alert.get('correlation', {}).get('is_correlated', False):
                        corr_info = alert['correlation']
                        corr_frame = ttk.Frame(inner_frame, padding=(0, 5, 0, 0))
                        corr_frame.pack(fill=tk.X, pady=(5, 0))
                        
                        # Style for correlation info
                        corr_style = "Severity.5.TLabel" if corr_info.get('attack_chain_complete', False) else "Severity.3.TLabel"
                        
                        corr_label = ttk.Label(
                            corr_frame, 
                            text=f"Part of attack chain: {corr_info.get('rule_name', 'Unknown')}",
                            style=corr_style
                        )
                        corr_label.pack(fill=tk.X)
                        
                        if corr_info.get('related_alerts'):
                            related = ", ".join(corr_info['related_alerts'])
                            related_label = ttk.Label(corr_frame, text=f"Related alerts: {related}", wraplength=700)
                            related_label.pack(fill=tk.X)
            
            # Add footer
            footer_frame = ttk.Frame(root, padding=10)
            footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
            
            ttk.Button(footer_frame, text="Open Dashboard", command=lambda: (root.destroy(), os.system("start http://localhost:5000"))).pack(side=tk.LEFT, padx=5)
            ttk.Button(footer_frame, text="Close", command=root.destroy).pack(side=tk.RIGHT, padx=5)
            
            # Center window on screen
            root.update_idletasks()
            width = root.winfo_width()
            height = root.winfo_height()
            x = (root.winfo_screenwidth() // 2) - (width // 2)
            y = (root.winfo_screenheight() // 2) - (height // 2)
            root.geometry(f'+{x}+{y}')
            
            # Run window
            root.mainloop()
        
        except Exception as e:
            logging.error(f"Error showing alerts window: {str(e)}")
            # Fallback to simple message box
            try:
                import ctypes
                message = "Could not show alerts window. Check the logs for details."
                ctypes.windll.user32.MessageBoxW(0, message, "LOLBins IDS - Error", 0)
            except:
                pass
    
    def send_notification(self, alert):
        """
        Send a notification through this provider
        
        Args:
            alert (dict): The alert data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Just add to queue, will be processed by thread
            self.notification_queue.put(alert)
            return True
        except Exception as e:
            logging.error(f"Error queuing system tray notification: {str(e)}")
            return False
    
    def shutdown(self):
        """Shut down the provider"""
        self.running = False
        if self.icon:
            self.icon.stop()


class SystemTrayProvider:
    """Provider for Windows system tray notifications with toast alerts"""
    
    def __init__(self, config):
        self.config = config
        self.toast = ToastNotifier()
        # Initialize other components as needed
    
    def send_notification(self, alert):
        """
        Send a notification through this provider
        
        Args:
            alert (dict): The alert data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            severity = alert.get('severity', 1)
            rule_name = alert.get('rule_name', 'Unknown Rule')
            process = alert.get('process_name', 'Unknown Process')
            description = alert.get('description', 'No description')
            
            # Format title based on severity
            if severity >= 5:
                title_prefix = "CRITICAL ALERT"
            elif severity >= 4:
                title_prefix = "HIGH SEVERITY ALERT"
            elif severity >= 3:
                title_prefix = "MEDIUM ALERT"
            else:
                title_prefix = "ALERT"
            
            title = f"{title_prefix}: {rule_name}"
            
            # Format message
            message = f"Process: {process}\n{description}"
            
            # Add correlation info if present
            if alert.get('correlation', {}).get('is_correlated', False):
                chain_info = alert['correlation']
                if chain_info.get('attack_chain_complete', False):
                    message += f"\n\nATTACK CHAIN DETECTED: {chain_info.get('rule_name', 'Unknown Attack Chain')}"
            
            # Define callback to open dashboard
            def open_dashboard():
                import webbrowser
                webbrowser.open("http://localhost:5000/alerts")
            
            # Show the notification
            self.toast.show_toast(
                title=title,
                msg=message,
                icon_path=None,  # None for default app icon
                duration=5,  # Show for 5 seconds
                threaded=True,
                callback_on_click=open_dashboard
            )
            return True
            
        except Exception as e:
            logging.error(f"Error showing toast notification: {str(e)}")
            return False

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
        "min_severity": 1,
        "max_recent_alerts": 10
    }
    
    # Create provider
    provider = SystemTrayProvider(test_config)
    
    # Test notification
    test_alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'rule_name': "PowerShell Encoded Command",
        'description': "PowerShell executing encoded commands",
        'severity': 4,
        'process_name': "powershell.exe",
        'command_line': "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
        'pid': 1234,
        'username': "test_user"
    }
    
    # Send notification
    provider.send_notification(test_alert)
    
    # Keep program running to see the notification
    print("Test notification sent. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass