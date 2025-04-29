import os
import json
from pathlib import Path

# Create the configuration directory
config_dir = Path("C:/ProgramData/LolbinIDS")
config_dir.mkdir(parents=True, exist_ok=True)

# Configuration content
config = {
    "notification_channels": {
        "system_tray": {
            "enabled": True,
            "min_severity": 1
        },
        "email": {
            "enabled": False,
            "min_severity": 3,
            "throttle_minutes": 15,
            "recipients": ["security-team@example.com"],
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_username": "alerts@example.com",
            "smtp_password": "your-password-here",
            "from_address": "lolbins-ids@example.com"
        },
        "websocket": {
            "enabled": True,
            "min_severity": 1,
            "port": 8765
        }
    },
    "alert_correlation": {
        "enabled": True,
        "time_window_minutes": 15,
        "min_alerts_to_correlate": 2
    },
    "history_retention_minutes": 60
}

# Write configuration to file
config_path = config_dir / "config.json"
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"Configuration created at {config_path}")