import shutil
import sys
import yaml

def check_disk_usage(threshold=0.7, path="."):
    """
    檢查指定路徑的磁碟使用率。
    如果使用率超過 threshold (0.0 - 1.0)，則回傳 False，否則回傳 True。
    """
    total, used, free = shutil.disk_usage(path)
    usage_ratio = used / total
    
    if usage_ratio >= threshold:
        print(f"\n[!] WARNING: Disk usage is at {usage_ratio:.1%}, which exceeds the threshold of {threshold:.1%}.")
        print("[!] Stopping script to prevent disk exhaustion.\n")
        return False
    
    print(f"[*] Disk usage: {usage_ratio:.1%} (Threshold: {threshold:.1%}) - Safe to proceed.")
    return True

def get_threshold_from_config():
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config.get("DISK_USAGE_THRESHOLD", 0.7)
    except:
        return 0.7
