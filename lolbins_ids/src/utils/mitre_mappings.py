# MITRE ATT&CK mappings for LOLBin techniques
MITRE_ATTACK_MAPPINGS = {
    "CertUtil Download": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "CertUtil Encoding/Decoding": {
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1140/"
    },
    "PowerShell Encoded Command": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "PowerShell Suspicious Command": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "Regsvr32 AppLocker Bypass": {
        "technique_id": "T1218.010",
        "technique_name": "System Binary Proxy Execution: Regsvr32",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1218/010/"
    },
    "MSHTA Suspicious Execution": {
        "technique_id": "T1218.005",
        "technique_name": "System Binary Proxy Execution: MSHTA",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1218/005/"
    },
    "WMIC Process Creation": {
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1047/"
    }
}