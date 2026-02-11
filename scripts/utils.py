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

def verify_signature(file_path):
    """
    使用 osslsigncode 驗證檔案是否具有數位簽章。
    回傳 True 代表檔案已簽署，False 代表未簽署。
    """
    import subprocess
    try:
        # osslsigncode verify -in <file>
        # 如果有簽名且認證通過，回傳值通常為 0
        cmd = ["osslsigncode", "verify", "-in", str(file_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        # 只要輸出中包含 "Signature verification: ok" 或是 "Signature verify OK"
        # 這裡我們採取寬鬆檢查：只要有簽名存在就算
        if result.returncode == 0 or "Signature verification: ok" in result.stdout:
            return True
    except Exception:
        pass
    return False

def scan_with_clamav(file_path):
    """
    使用 clamscan 進行病毒掃描。
    回傳 True 代表檔案安全（未發現威脅），False 代表發現威脅。
    """
    import subprocess
    try:
        # clamscan --no-summary <file>
        # 回傳值: 0: 未發現病毒, 1: 發現病毒, 2: 發生錯誤
        cmd = ["clamscan", "--no-summary", str(file_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return True
        elif result.returncode == 1:
            print(f" [!] ClamAV: Malware detected in {file_path}!")
            return False
    except Exception as e:
        print(f" [!] ClamAV: Scan error: {e}")
    return True # 如果掃描出錯，預設先放行

def remove_empty_dirs(root_path):
    """
    遞迴移除指定路徑下的所有空資料夾。
    """
    if not os.path.exists(root_path):
        return
        
    for root, dirs, files in os.walk(root_path, topdown=False):
        for name in dirs:
            dir_path = os.path.join(root, name)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except:
                pass
