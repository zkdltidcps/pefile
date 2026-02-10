import os
import requests
import yaml
import zipfile
import io
import time
import json
from pathlib import Path
from utils import check_disk_usage, get_threshold_from_config, is_pe_file

HISTORY_FILE = Path("benign_pe/metadata/history_github.json")

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

def download_and_extract(url, target_dir, enable_download, history):
    if url in history:
        print(f"  [SKIP] Already downloaded: {url}")
        return False

    if not enable_download:
        print(f"  [DRY RUN] Would download: {url}")
        return False

    print(f"  Downloading: {url}")
    try:
        response = requests.get(url, stream=True, timeout=30)
        if response.status_code != 200:
            print(f"  Failed to download {url}")
            return False

        success = False
        # 檢查是否為 zip
        if url.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                extracted_any = False
                for file_info in z.infolist():
                    if any(file_info.filename.lower().endswith(ext) for ext in [".exe", ".dll", ".sys"]):
                        z.extract(file_info, target_dir)
                        
                        # 嚴格驗證 PE 簽章
                        if is_pe_file(extracted_path):
                            print(f"   Extracted and verified: {file_info.filename}")
                            extracted_any = True
                        else:
                            print(f"   [DELETE] Not a valid PE: {file_info.filename}")
                            os.remove(extracted_path)
                success = extracted_any
        else:
            # 單一檔案直接存
            file_name = url.split("/")[-1]
            dest_path = target_dir / file_name
            content = response.content

            with open(dest_path, 'wb') as f:
                f.write(content)
            
            # 嚴格驗證 PE 簽章
            if is_pe_file(dest_path):
                print(f"   Saved and verified: {file_name}")
                success = True
            else:
                print(f"   [DELETE] Not a valid PE: {file_name}")
                os.remove(dest_path)
                success = False
        
        if success:
            history.add(url)
            save_history(history)
            return True
            
    except Exception as e:
        print(f"  Error during download/extract: {e}")
    return False

def get_automated_repos(config):
    discovery = config.get("DISCOVERY_SETTINGS", {})
    min_stars = discovery.get("MIN_STARS", 500)
    queries = discovery.get("QUERIES", ["topic:windows"])
    max_repos = discovery.get("MAX_REPOS_PER_RUN", 10)
    
    found_repos = []
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    
    for query in queries:
        search_url = f"https://api.github.com/search/repositories?q={query}+stars:>{min_stars}&sort=stars&order=desc&per_page=30"
        print(f"Searching for repos with query: {query}")
        
        try:
            res = requests.get(search_url, headers=headers, timeout=15)
            if res.status_code == 200:
                items = res.json().get("items", [])
                for item in items:
                    repo_full_name = item.get("full_name")
                    if repo_full_name not in found_repos:
                        found_repos.append(repo_full_name)
                        if len(found_repos) >= max_repos:
                            break
            else:
                print(f" Search failed for {query}: {res.status_code}")
        except Exception as e:
            print(f" Error during discovery: {e}")
        
        if len(found_repos) >= max_repos:
            break
            
    return found_repos

def main():
    config = load_config()
    enable_download = config.get("ENABLE_DOWNLOAD", False)
    threshold = get_threshold_from_config()
    history = load_history()
    
    if enable_download and not check_disk_usage(threshold):
        return

    # 1. 全自動發現 Repo
    repos = get_automated_repos(config)
    print(f"\nDiscovered {len(repos)} repositories to process.")
    
    base_dir = Path("benign_pe/github_release")
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    download_total = 0

    # 2. 遍歷每一個發現的 Repo
    for repo in repos:
        print(f"\n--- Checking Repo: {repo} ---")
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        
        try:
            res = requests.get(api_url, headers=headers, timeout=15)
            if res.status_code == 200:
                release_data = res.json()
                assets = release_data.get("assets", [])
                
                repo_name = repo.split("/")[-1]
                target_dir = base_dir / repo_name
                target_dir.mkdir(parents=True, exist_ok=True)

                for asset in assets:
                    asset_url = asset.get("browser_download_url")
                    if any(asset_url.lower().endswith(ext) for ext in [".exe", ".dll", ".zip", ".msi"]):
                        if download_and_extract(asset_url, target_dir, enable_download, history):
                            download_total += 1
            
            elif res.status_code == 404:
                print(f" No releases found for {repo}.")
        except Exception as e:
            print(f" Error processing {repo}: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    main()
