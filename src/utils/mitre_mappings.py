"""
Module providing MITRE ATT&CK® framework mappings for LOLBin activities.
"""

# Dictionary mapping LOLBin names to their MITRE techniques
LOLBIN_MITRE_MAPPINGS = {
    "certutil.exe": ["T1140", "T1105", "T1553.004"],
    "regsvr32.exe": ["T1218.010"],
    "rundll32.exe": ["T1218.011"],
    "mshta.exe": ["T1218.005"],
    "msiexec.exe": ["T1218.007"],
    "powershell.exe": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "wmic.exe": ["T1047"],
    "bitsadmin.exe": ["T1197"],
    # Add more as needed
}

def get_technique_info(technique_id):
    """
    Get information about a MITRE technique based on its ID.
    
    Args:
        technique_id (str): The MITRE technique ID (e.g. 'T1140')
        
    Returns:
        dict: Information about the technique
    """
    # This would normally fetch from a database or API
    # Simplified version for demonstration
    techniques = {
        "T1140": {
            "name": "Deobfuscate/Decode Files or Information",
            "tactic": "Defense Evasion",
            "description": "Adversaries may use obfuscated files or information to hide artifacts of an intrusion"
        },
        # Add more techniques as needed
    }
    
    return techniques.get(technique_id, {"name": "Unknown", "tactic": "Unknown", "description": "No information available"})

def get_mitre_techniques_for_lolbin(lolbin_name):
    """
    Get the MITRE techniques associated with a specific LOLBin.
    
    Args:
        lolbin_name (str): The name of the LOLBin (e.g., 'certutil.exe')
        
    Returns:
        list: List of associated MITRE technique IDs
    """
    return LOLBIN_MITRE_MAPPINGS.get(lolbin_name.lower(), [])
