import logging
import threading
import queue
import time
from datetime import datetime

class TkinterNotifierProvider:
    """Simple notification provider using Tkinter dialogs"""
    
    def __init__(self, config):
        self.config = config
        self.alert_queue = queue.Queue()
        self.min_severity = config.get('min_severity', 1)
        
        # Start notification processing thread
        self.running = True
        self.notification_thread = threading.Thread(target=self._process_notifications)
        self.notification_thread.daemon = True
        self.notification_thread.start()
        
        logging.info("Tkinter notifier initialized")
    
    def _process_notifications(self):
        """Process notifications from the queue"""
        while self.running:
            try:
                # Get notification with timeout
                try:
                    alert = self.alert_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Show the notification
                self._show_alert_window(alert)
                
                # Mark as done
                self.alert_queue.task_done()
                
            except Exception as e:
                logging.error(f"Error processing notification: {str(e)}")
                time.sleep(1)  # Prevent busy-waiting on error
    
    def _show_alert_window(self, alert):
        """Show a tkinter window with the alert details"""
        try:
            # Import tkinter inside the method to avoid loading it in non-GUI environments
            import tkinter as tk
            from tkinter import font
            
            # Get alert details
            severity = alert.get('severity', 1)
            rule_name = alert.get('rule_name', 'Unknown Rule')
            process = alert.get('process_name', 'Unknown Process')
            description = alert.get('description', 'No description')
            command = alert.get('command_line', '')
            timestamp = alert.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Format title based on severity
            if severity >= 5:
                title_prefix = "CRITICAL ALERT"
                bg_color = "#d32f2f"  # Red
            elif severity >= 4:
                title_prefix = "HIGH SEVERITY ALERT"
                bg_color = "#f57c00"  # Orange
            elif severity >= 3:
                title_prefix = "MEDIUM ALERT"
                bg_color = "#ffa000"  # Amber
            else:
                title_prefix = "ALERT"
                bg_color = "#0288d1"  # Blue
            
            # Create root window
            root = tk.Tk()
            root.title(f"LOLBins IDS - {title_prefix}")
            root.geometry("600x400")
            root.minsize(500, 300)
            
            # Set window to appear on top
            root.attributes("-topmost", True)
            
            # Create fonts
            title_font = font.Font(family="Arial", size=12, weight="bold")
            header_font = font.Font(family="Arial", size=11, weight="bold")
            normal_font = font.Font(family="Arial", size=10)
            code_font = font.Font(family="Courier", size=9)
            
            # Main frame
            main_frame = tk.Frame(root, padx=20, pady=20)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Title frame with colored background
            title_frame = tk.Frame(main_frame, bg=bg_color, padx=10, pady=10)
            title_frame.pack(fill=tk.X)
            
            tk.Label(
                title_frame, 
                text=f"{title_prefix}: {rule_name}", 
                font=title_font, 
                bg=bg_color, 
                fg="white"
            ).pack(anchor=tk.W)
            
            tk.Label(
                title_frame,
                text=f"Detected at {timestamp}",
                font=normal_font,
                bg=bg_color,
                fg="white"
            ).pack(anchor=tk.W)
            
            # Content frame
            content_frame = tk.Frame(main_frame, padx=10, pady=10)
            content_frame.pack(fill=tk.BOTH, expand=True)
            
            # Description
            tk.Label(
                content_frame,
                text="Description:",
                font=header_font
            ).pack(anchor=tk.W, pady=(10, 0))
            
            tk.Label(
                content_frame,
                text=description,
                font=normal_font,
                wraplength=550,
                justify=tk.LEFT
            ).pack(anchor=tk.W, padx=10)
            
            # Process info
            process_frame = tk.Frame(content_frame)
            process_frame.pack(fill=tk.X, pady=(10, 0))
            
            tk.Label(
                process_frame,
                text="Process:",
                font=header_font
            ).pack(side=tk.LEFT)
            
            tk.Label(
                process_frame,
                text=f"{process} (PID: {alert.get('pid', 'Unknown')})",
                font=normal_font
            ).pack(side=tk.LEFT, padx=(5, 0))
            
            # User info
            user_frame = tk.Frame(content_frame)
            user_frame.pack(fill=tk.X, pady=(5, 0))
            
            tk.Label(
                user_frame,
                text="User:",
                font=header_font
            ).pack(side=tk.LEFT)
            
            tk.Label(
                user_frame,
                text=alert.get('username', 'Unknown'),
                font=normal_font
            ).pack(side=tk.LEFT, padx=(5, 0))
            
            # Command
            if command:
                tk.Label(
                    content_frame,
                    text="Command:",
                    font=header_font
                ).pack(anchor=tk.W, pady=(10, 0))
                
                cmd_text = tk.Text(content_frame, height=3, font=code_font, wrap=tk.WORD)
                cmd_text.insert(tk.END, command)
                cmd_text.config(state=tk.DISABLED)
                cmd_text.pack(fill=tk.X, padx=10, pady=(5, 0))
            
            # Button frame
            button_frame = tk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            # Close button
            close_button = tk.Button(
                button_frame,
                text="Close",
                command=root.destroy,
                width=10
            )
            close_button.pack(side=tk.RIGHT)
            
            # Auto-close after 30 seconds
            root.after(30000, root.destroy)
            
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
            logging.error(f"Error showing alert window: {str(e)}")
    
    def send_notification(self, alert):
        """
        Send a notification through this provider
        
        Args:
            alert (dict): The alert data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if severity meets threshold
            if alert.get('severity', 1) < self.min_severity:
                return True
                
            # Add to queue for processing
            self.alert_queue.put(alert)
            return True
        except Exception as e:
            logging.error(f"Error queuing tkinter notification: {str(e)}")
            return False