import shutil
import sys
import yaml
import os

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

def is_pe_file(file_path):
    """
    讀取檔案開頭，檢查是否為有效的 Windows PE 檔案 (MZ + PE header)。
    """
    try:
        if not os.path.exists(file_path):
            return False
            
        with open(file_path, 'rb') as f:
            # 檢查 MZ 簽章
            if f.read(2) != b'MZ':
                return False
            
            # 尋找 PE header offset
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return False
            
            import struct
            pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
            
            # 檢查 PE 簽章
            f.seek(pe_offset)
            if f.read(4) != b'PE\0\0':
                return False
                
        return True
    except Exception:
        return False
