import os
from pathlib import Path
from utils import is_pe_file, verify_signature, scan_with_clamav, remove_empty_dirs

def main():
    base_dir = Path("benign_pe")
    if not base_dir.exists():
        print("Base directory 'benign_pe' does not exist.")
        return

    print("=== Retroactive Dataset Sanitization Starting ===")
    
    stats = {
        "total": 0,
        "kept": 0,
        "deleted_pe": 0,
        "deleted_malware": 0
    }

    # Walk through all files in benign_pe/
    for root, dirs, files in os.walk(base_dir):
        # Skip metadata
        if "metadata" in root:
            continue

        for name in files:
            file_path = Path(root) / name
            stats["total"] += 1

            # 1. PE Validation
            if not is_pe_file(file_path):
                print(f" [DELETE] Invalid PE: {file_path}")
                os.remove(file_path)
                stats["deleted_pe"] += 1
                continue

            # 2. ClamAV Scan
            # ClamAV is our primary gatekeeper for "benign" status
            if not scan_with_clamav(file_path):
                print(f" [DELETE] Malware Detected: {file_path}")
                os.remove(file_path)
                stats["deleted_malware"] += 1
                continue

            # 3. Signature verification (Informational)
            signed = " (Signed)" if verify_signature(file_path) else " (Unsigned)"
            print(f" [KEEP] Verified: {file_path}{signed}")
            stats["kept"] += 1

    # Cleanup empty dirs
    remove_empty_dirs(base_dir)

    print("\n=== Sanitization Complete ===")
    print(f"Total files checked: {stats['total']}")
    print(f"Files kept:          {stats['kept']}")
    print(f"Deleted (Not PE):    {stats['deleted_pe']}")
    print(f"Deleted (Malware):   {stats['deleted_malware']}")

if __name__ == "__main__":
    main()
