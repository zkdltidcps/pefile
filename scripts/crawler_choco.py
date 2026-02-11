import os
import requests
import yaml
import zipfile
import io
import json
import time
from pathlib import Path
from utils import check_disk_usage, get_threshold_from_config, is_pe_file, remove_empty_dirs

HISTORY_FILE = Path("benign_pe/metadata/history_choco.json")
STATE_FILE = Path("benign_pe/metadata/discovery_state.json")

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

def load_discovery_state():
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {}

def save_discovery_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except:
        pass

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
            print(f"  Failed to download {url} (HTTP {response.status_code})")
            if response.status_code in [403, 429]:
                return "RATE_LIMIT"
            return False

        # nupkg 是一個 zip 檔案
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            extracted_any = False
            for file_info in z.infolist():
                # 排除 macOS 系統垃圾檔案
                if "__MACOSX" in file_info.filename or os.path.basename(file_info.filename).startswith("._"):
                    continue
                    
                # 只有副檔名在允許清單內的才解壓
                if any(file_info.filename.lower().endswith(ext) for ext in [".exe", ".dll", ".sys"]):
                    # 避免解壓到外部
                    # The original code used os.path.basename, but z.extract handles paths within the zip.
                    # We need to ensure the full path is used for extraction and subsequent PE check.
                    if not file_info.is_dir(): # Only process files, not directories
                        if not target_dir.exists():
                            target_dir.mkdir(parents=True, exist_ok=True)
                        z.extract(file_info, target_dir)
                        extracted_path = target_dir / file_info.filename
                        
                        if is_pe_file(extracted_path):
                            print(f"   Extracted and verified: {file_info.filename}")
                            extracted_any = True # Only count as extracted if it's a valid PE
                        else:
                            print(f"   [DELETE] Not a valid PE: {file_info.filename}")
                            os.remove(extracted_path)
            
            if extracted_any:
                history.add(url)
                save_history(history)
                return True
    except Exception as e:
        print(f"  Error processing nupkg: {e}")
    return False

def get_choco_packages(config):
    choco_conf = config.get("CHOCO_SETTINGS", {})
    query = choco_conf.get("QUERY", "")
    max_pkgs = choco_conf.get("MAX_PACKAGES_PER_RUN", 5)
    
    state = load_discovery_state()
    choco_state = state.get("choco", {})
    current_skip = choco_state.get("skip", 0)
    
    # 使用 NuGet V3 API 搜尋
    search_url = f"https://azuresearch-usnc.nuget.org/query?q={query}&take={max_pkgs}&skip={current_skip}&prerelease=false"
    print(f"Fetching Chocolatey packages (Skip: {current_skip}, Take: {max_pkgs})")
    
    packages = []
    
    try:
        res = requests.get(search_url, timeout=15)
        if res.status_code == 200:
            data = res.json()
            items = data.get("data", [])
            if not items:
                # 沒東西了就從頭開始
                choco_state["skip"] = 0
            else:
                for item in items:
                    pkg_id = item.get("id")
                    version = item.get("version")
                    download_url = f"https://www.nuget.org/api/v2/package/{pkg_id}/{version}"
                    packages.append({"id": pkg_id, "url": download_url})
                # 下一輪繼續往下跳
                choco_state["skip"] = current_skip + max_pkgs
        else:
            print(f" [!] Chocolatey Search API Error: HTTP {res.status_code}")
            if res.status_code in [403, 429]:
                print("  [!] Rate Limit or Access Blocked by NuGet. Skipping Choco for this cycle.")
                return [] # Return empty to stop this run
    except Exception as e:
        print(f"Error fetching choco packages: {e}")
        
    state["choco"] = choco_state
    save_discovery_state(state)
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
        # target_dir.mkdir(parents=True, exist_ok=True) # <-- 改為延遲建立
        
        result = download_and_extract_nupkg(pkg['url'], target_dir, enable_download, history)
        if result == "RATE_LIMIT":
            print(" [!] Rate Limit hit during download. Stopping Choco cycle.")
            break
        
        time.sleep(1)
        
    # 執行完畢後清理空資料夾
    remove_empty_dirs(base_dir)

if __name__ == "__main__":
    main()
