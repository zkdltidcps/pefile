import shutil
import platform
import os
import subprocess
import requests
import json

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

def check_server():
    print("=== Server Diagnostic Report ===")
    
    # 1. System Info
    print(f"\n[System]")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Machine: {platform.machine()}")
    
    # 2. Disk Usage
    print(f"\n[Disk Usage]")
    total, used, free = shutil.disk_usage(".")
    print(f"Total: {get_size(total)}")
    print(f"Used: {get_size(used)} ({used/total:.1%})")
    print(f"Free: {get_size(free)} ({free/total:.1%})")
    
    # 3. Environment Status
    print(f"\n[Environment]")
    print(f"User ID: {os.getuid()}")
    print(f"Working Dir: {os.getcwd()}")
    try:
        import yaml
        print("PyYAML: Installed")
    except:
        print("PyYAML: Missing")
        
    # 4. Network Connectivity
    print(f"\n[Network Connectivity]")
    targets = {
        "GitHub API": "https://api.github.com",
        "NuGet V3": "https://api.nuget.org/v3/index.json",
        "PortableApps": "https://portableapps.com"
    }
    
    for name, url in targets.items():
        try:
            res = requests.get(url, timeout=5)
            status = "OK" if res.status_code == 200 else f"HTTP {res.status_code}"
            print(f"{name}: {status}")
        except Exception as e:
            print(f"{name}: Failed ({type(e).__name__})")

if __name__ == "__main__":
    check_server()
