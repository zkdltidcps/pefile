import os
import requests
import yaml
import json
import time
from pathlib import Path
from bs4 import BeautifulSoup
import re
from utils import check_disk_usage, get_threshold_from_config, is_pe_file

HISTORY_FILE = Path("benign_pe/metadata/history_portable.json")

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

def download_file(url, target_dir, enable_download, history):
    if url in history:
        print(f"  [SKIP] Already downloaded: {url}")
        return False

    if not enable_download:
        print(f"  [DRY RUN] Would download: {url}")
        return False

    print(f"  Downloading: {url}")
    try:
        # PortableApps 通常會跳轉到 SourceForge
        response = requests.get(url, stream=True, timeout=60, allow_redirects=True)
        if response.status_code != 200:
            print(f"  Failed to download {url} (Status: {response.status_code})")
            return False

        # 從 Header 或 URL 取得檔名
        url_path = url.split("?")[0]
        file_name = url_path.split("/")[-1]
        
        # 針對 PortableApps 的參數做解析
        if "f=" in url:
            from urllib.parse import parse_qs, urlparse
            params = parse_qs(urlparse(url).query)
            if 'f' in params:
                file_name = params['f'][0]

        if not file_name or file_name == "" or file_name == "redir2":
             # 嘗試從 content-disposition 抓
             cd = response.headers.get("content-disposition")
             if cd:
                 fname_match = re.findall("filename=(.+)", cd)
                 if fname_match:
                     file_name = fname_match[0].strip(' "')

        if not file_name:
            file_name = "downloaded_app.exe"

        dest_path = target_dir / file_name
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # 嚴格驗證 PE 簽章
        if is_pe_file(dest_path):
            print(f"   Saved and verified: {file_name}")
            history.add(url)
            save_history(history)
            return True
        else:
            print(f"   [DELETE] Not a valid PE: {file_name}")
            os.remove(dest_path)
            return False
    except Exception as e:
        print(f"  Error during download: {e}")
    return False

def get_portable_apps(config):
    p_conf = config.get("PORTABLEAPPS_SETTINGS", {})
    base_url = p_conf.get("BASE_URL", "https://portableapps.com/apps")
    target_categories = p_conf.get("CATEGORIES", [])
    max_apps = p_conf.get("MAX_APPS_PER_RUN", 5)
    
    apps = []
    try:
        res = requests.get(base_url, timeout=20)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            # 遍歷所有的 h2 分類標題
            for h2 in soup.find_all('h2'):
                full_cat_text = h2.get_text(strip=True)
                
                # 比對分類 (只要包含關鍵字即可)
                is_target = False
                if not target_categories:
                    is_target = True
                else:
                    for target in target_categories:
                        if target.lower() in full_cat_text.lower():
                            is_target = True
                            break
                
                if not is_target:
                    continue
                
                # 尋找 h2 之後的下一個清單或區塊
                # 通常在 view-grouping-content 或直接是下一個結構
                parent_section = h2.find_parent('div', class_='view-grouping')
                if not parent_section:
                    parent_section = h2.parent # 備案

                for app_link in parent_section.find_all('a', href=re.compile(r"^/apps/")):
                    # 排除 "View by Category" 這種導覽連結
                    if "View by Category" in app_link.get_text():
                        continue
                        
                    app_name = app_link.get_text(strip=True)
                    if not app_name or len(app_name) < 2: continue
                    
                    app_page_url = "https://portableapps.com" + app_link['href']
                    # 避免重複
                    if not any(a['url'] == app_page_url for a in apps):
                        apps.append({"name": app_name, "url": app_page_url})
                        print(f" Found: {app_name} ({app_page_url})")
                    
                    if len(apps) >= max_apps:
                        return apps
    except Exception as e:
        print(f"Error scraping PortableApps: {e}")
        
    return apps

def get_download_url(app_page_url):
    try:
        res = requests.get(app_page_url, timeout=15)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # 優先搜尋包含 "Download from" 關鍵字的連結
            for link in soup.find_all('a'):
                link_text = link.get_text(strip=True)
                href = link.get('href', '')
                
                if "Download from" in link_text and "/downloading" in href:
                    downloading_url = href
                    if downloading_url.startswith("/"):
                        downloading_url = "https://portableapps.com" + downloading_url
                    
                    # 進入中間跳轉頁面尋找真正的下載點 (SourceForge 或官網)
                    print(f"  Found redirect page: {downloading_url}")
                    try:
                        res_redirect = requests.get(downloading_url, timeout=15)
                        if res_redirect.status_code == 200:
                            soup_inner = BeautifulSoup(res_redirect.text, 'html.parser')
                            # 尋找 "click here" 或是直接的跳轉連結
                            # 通常包含 sourceforge.net 或 github.com 或 .paf.exe
                            for inner_link in soup_inner.find_all('a'):
                                inner_href = inner_link.get('href', '')
                                if "sourceforge.net" in inner_href or ".paf.exe" in inner_href or "/redir" in inner_href:
                                     if inner_href.startswith("/"):
                                         inner_href = "https://portableapps.com" + inner_href
                                     return inner_href
                    except:
                        pass
                    return downloading_url # 退而求其次
            
            # 備選方案：找 download-link class
            download_btn = soup.find('a', class_='download-link')
            if download_btn and download_btn.has_attr('href'):
                return download_btn['href']
    except Exception as e:
        print(f" Error fetching download page for {app_page_url}: {e}")
    return None

def main():
    config = load_config()
    enable_download = config.get("ENABLE_DOWNLOAD", False)
    threshold = get_threshold_from_config()
    history = load_history()
    
    if enable_download and not check_disk_usage(threshold):
        return

    apps = get_portable_apps(config)
    print(f"\nDiscovered {len(apps)} PortableApps to process.")
    
    base_dir = Path("benign_pe/portableapps")
    base_dir.mkdir(parents=True, exist_ok=True)

    for app in apps:
        print(f"\n--- Processing App: {app['name']} ---")
        # 進入 App 頁面找下載連結
        real_download_url = get_download_url(app['url'])
        
        if real_download_url:
            target_dir = base_dir / app['name'].replace(" ", "_").replace("/", "_")
            target_dir.mkdir(parents=True, exist_ok=True)
            download_file(real_download_url, target_dir, enable_download, history)
        else:
            print("  Could not find download URL.")
        
        time.sleep(2)

if __name__ == "__main__":
    main()
