# Directory: src/notification/providers/websocket_provider.py

import json
import socketio

class WebSocketProvider:
    def __init__(self, config=None):
        self.server_url = "http://localhost:5000"  # Dashboard server address
        self.namespace = "/alerts"
        self.sio = socketio.Client()
        try:
            self.sio.connect(self.server_url, namespaces=[self.namespace])
        except Exception as e:
            print(f"[WebSocketProvider] Warning: Could not connect to WebSocket server ({self.server_url}) - {e}")

    def send_notification(self, alert_data):
        try:
            if self.sio.connected:
                self.sio.emit("new_alert", json.dumps(alert_data), namespace=self.namespace)
                print("[WebSocketProvider] Alert sent via WebSocket")
            else:
                print("[WebSocketProvider] Not connected to WebSocket server")
        except Exception as e:
            print(f"[WebSocketProvider] Error sending WebSocket notification: {e}")

    def shutdown(self):
        try:
            self.sio.disconnect()
        except Exception:
            pass
