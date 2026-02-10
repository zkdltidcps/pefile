import os
import requests
import yaml
import zipfile
import io
import json
import time
from pathlib import Path
from utils import check_disk_usage, get_threshold_from_config

HISTORY_FILE = Path("benign_pe/metadata/history_choco.json")

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def load_history():
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r") as f:
                return set(json.load(f))
        except Exception as e:
            print(f"Error loading history: {e}")
    return set()

def save_history(history):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(list(history), f, indent=2)
    except Exception as e:
        print(f"Error saving history: {e}")

def download_and_extract_nupkg(url, target_dir, enable_download, history):
    if url in history:
        print(f"  [SKIP] Already processed: {url}")
        return False

    if not enable_download:
        print(f"  [DRY RUN] Would download nupkg: {url}")
        return False

    print(f"  Downloading nupkg: {url}")
    try:
        response = requests.get(url, timeout=60)
        if response.status_code != 200:
            print(f"  Failed to download {url}")
            return False

        # nupkg 是一個 zip 檔案
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            extracted_any = False
            for file_info in z.infolist():
                # 只有副檔名在允許清單內的才解壓
                if any(file_info.filename.lower().endswith(ext) for ext in [".exe", ".dll", ".sys"]):
                    # 避免解壓到外部
                    filename = os.path.basename(file_info.filename)
                    if filename:
                        with open(target_dir / filename, "wb") as f:
                            f.write(z.read(file_info))
                        print(f"   Extracted: {filename}")
                        extracted_any = True
            
            if extracted_any:
                history.add(url)
                save_history(history)
                return True
    except Exception as e:
        print(f"  Error processing nupkg: {e}")
    return False

def get_choco_packages(config):
    choco_conf = config.get("CHOCO_SETTINGS", {})
    query = choco_conf.get("QUERY", "tags:chocolatey")
    max_pkgs = choco_conf.get("MAX_PACKAGES_PER_RUN", 5)
    
    # 使用 NuGet V3 API 搜尋
    search_url = f"https://azuresearch-usnc.nuget.org/query?q={query}&take={max_pkgs}&prerelease=false"
    packages = []
    
    try:
        res = requests.get(search_url, timeout=15)
        if res.status_code == 200:
            data = res.json()
            for item in data.get("data", []):
                pkg_id = item.get("id")
                # 獲取最新版本
                version = item.get("version")
                # 構建下載連結 (標準 NuGet 格式)
                # 格式: https://www.nuget.org/api/v2/package/{ID}/{VERSION}
                download_url = f"https://www.nuget.org/api/v2/package/{pkg_id}/{version}"
                packages.append({"id": pkg_id, "url": download_url})
    except Exception as e:
        print(f"Error fetching choco packages: {e}")
        
    return packages

def main():
    config = load_config()
    enable_download = config.get("ENABLE_DOWNLOAD", False)
    threshold = get_threshold_from_config()
    history = load_history()
    
    if enable_download and not check_disk_usage(threshold):
        return

    packages = get_choco_packages(config)
    print(f"\nFound {len(packages)} Chocolatey packages to process.")
    
    base_dir = Path("benign_pe/chocolatey")
    base_dir.mkdir(parents=True, exist_ok=True)

    for pkg in packages:
        print(f"\n--- Processing Package: {pkg['id']} ---")
        target_dir = base_dir / pkg['id']
        target_dir.mkdir(parents=True, exist_ok=True)
        
        download_and_extract_nupkg(pkg['url'], target_dir, enable_download, history)
        time.sleep(1)

if __name__ == "__main__":
    main()
