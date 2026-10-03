import os
import sqlite3
import json
import re
from datetime import datetime, timezone
import pandas as pd

from .utils import (
    copy_db_file,
    get_chrome_master_key,
    decrypt_aes_gcm,
    webkit_timestamp_to_iso,
    firefox_timestamp_to_iso,
    unix_timestamp_to_iso
)

class BrowserParser:
    def __init__(self, temp_dir: str):
        self.temp_dir = temp_dir
        self.user_profile = os.environ.get('USERPROFILE', '')
        self.local_appdata = os.environ.get('LOCALAPPDATA', '')
        self.roaming_appdata = os.environ.get('APPDATA', '')

    def get_chrome_path(self) -> str:
        return os.path.join(self.local_appdata, 'Google', 'Chrome', 'User Data')

    def get_edge_path(self) -> str:
        return os.path.join(self.local_appdata, 'Microsoft', 'Edge', 'User Data')

    def get_firefox_path(self) -> str:
        return os.path.join(self.roaming_appdata, 'Mozilla', 'Firefox', 'Profiles')

    def scan_chrome_edge_profiles(self, user_data_path: str) -> list:
        """Finds all active Chrome/Edge profiles (Default, Profile 1, etc.)"""
        if not os.path.exists(user_data_path):
            return []
        
        profiles = []
        try:
            for item in os.listdir(user_data_path):
                item_path = os.path.join(user_data_path, item)
                if os.path.isdir(item_path):
                    if item == 'Default' or item.startswith('Profile '):
                        # Verify profile has a History db
                        if os.path.exists(os.path.join(item_path, 'History')):
                            profiles.append(item)
        except Exception as e:
            print(f"Error scanning profiles in {user_data_path}: {e}")
        return profiles

    def scan_firefox_profiles(self, profiles_root: str) -> list:
        """Finds all active Firefox profiles"""
        if not os.path.exists(profiles_root):
            return []
        
        profiles = []
        try:
            for item in os.listdir(profiles_root):
                item_path = os.path.join(profiles_root, item)
                if os.path.isdir(item_path):
                    if os.path.exists(os.path.join(item_path, 'places.sqlite')):
                        profiles.append(item)
        except Exception as e:
            print(f"Error scanning Firefox profiles in {profiles_root}: {e}")
        return profiles

    def parse_chrome_edge(self, browser_name: str, user_data_path: str, profile_name: str) -> dict:
        """Parses History, Downloads, Cookies, Autofill, and Logins for a Chrome/Edge profile."""
        profile_path = os.path.join(user_data_path, profile_name)
        results = {
            'history': [],
            'downloads': [],
            'cookies': [],
            'autofill': [],
            'logins': [],
            'deleted_gaps': 0
        }
        
        # Check files
        history_src = os.path.join(profile_path, 'History')
        cookies_src_network = os.path.join(profile_path, 'Network', 'Cookies')
        cookies_src_root = os.path.join(profile_path, 'Cookies')
        cookies_src = cookies_src_network if os.path.exists(cookies_src_network) else cookies_src_root
        web_data_src = os.path.join(profile_path, 'Web Data')
        logins_src = os.path.join(profile_path, 'Login Data')
        local_state_src = os.path.join(user_data_path, 'Local State')
        
        # Copy to temp in read-only mode
        history_temp = copy_db_file(history_src, self.temp_dir)
        cookies_temp = copy_db_file(cookies_src, self.temp_dir)
        web_data_temp = copy_db_file(web_data_src, self.temp_dir)
        logins_temp = copy_db_file(logins_src, self.temp_dir)
        
        # Get Master Decryption Key
        master_key = None
        if os.path.exists(local_state_src):
            try:
                local_state_temp = os.path.join(self.temp_dir, f"{browser_name}_Local_State")
                import shutil
                shutil.copy2(local_state_src, local_state_temp)
                master_key = get_chrome_master_key(local_state_temp)
            except Exception as e:
                print(f"[{browser_name}] Failed to get master key: {e}")
        
        # 1. Parse History & Detect Gaps
        if history_temp and os.path.exists(history_temp):
            conn = None
            try:
                # Use query mode=ro
                conn = sqlite3.connect(f"file:{history_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                
                # Query history visits
                cursor.execute("""
                    SELECT v.id, u.url, u.title, v.visit_time, v.visit_duration, u.visit_count, u.typed_count
                    FROM visits v
                    LEFT JOIN urls u ON v.url = u.id
                    ORDER BY v.visit_time DESC
                """)
                for row in cursor.fetchall():
                    results['history'].append({
                        'timestamp': webkit_timestamp_to_iso(row[3]),
                        'url': row[1] or "Unknown",
                        'title': row[2] or "",
                        'visit_duration': round(row[4] / 1000000.0, 2) if row[4] else 0, # microsecs to secs
                        'visit_count': row[5] or 0,
                        'typed_count': row[6] or 0,
                        'browser': f"{browser_name} ({profile_name})",
                        'source': 'History'
                    })
                
                # Check for deleted entry ID gaps in urls table
                cursor.execute("SELECT id FROM urls ORDER BY id")
                urls_ids = [r[0] for r in cursor.fetchall()]
                if urls_ids:
                    # Look for gaps in sequence
                    gaps = 0
                    for idx in range(1, len(urls_ids)):
                        diff = urls_ids[idx] - urls_ids[idx-1]
                        if diff > 1:
                            gaps += (diff - 1)
                    results['deleted_gaps'] = gaps
            except Exception as e:
                print(f"Error parsing History for {browser_name}: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 2. Parse Downloads
        if history_temp and os.path.exists(history_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{history_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                # Query downloads (different schema versions might have different columns, handle gracefully)
                try:
                    cursor.execute("""
                        SELECT id, target_path, start_time, received_bytes, total_bytes, state, referrer, site_url
                        FROM downloads
                        ORDER BY start_time DESC
                    """)
                    for row in cursor.fetchall():
                        target_path = row[1] or ""
                        filename = os.path.basename(target_path) if target_path else "Unknown"
                        state_val = row[5]
                        state_str = "Completed" if state_val == 1 else "Interrupted" if state_val == 4 else "In Progress" if state_val == 0 else f"State {state_val}"
                        results['downloads'].append({
                            'timestamp': webkit_timestamp_to_iso(row[2]),
                            'file_name': filename,
                            'target_path': target_path,
                            'received_bytes': row[3] or 0,
                            'total_bytes': row[4] or 0,
                            'state': state_str,
                            'referrer': row[6] or "",
                            'site_url': row[7] or "",
                            'browser': f"{browser_name} ({profile_name})",
                            'source': 'Download'
                        })
                except sqlite3.OperationalError as db_e:
                    # In older schemas, downloads is structured differently
                    print(f"Skipping downloads parse or old schema: {db_e}")
            except Exception as e:
                print(f"Error parsing Downloads for {browser_name}: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 3. Parse Cookies
        if cookies_temp and os.path.exists(cookies_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{cookies_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly, last_access_utc, encrypted_value
                    FROM cookies
                    ORDER BY creation_utc DESC
                """)
                for row in cursor.fetchall():
                    enc_val = row[8]
                    decrypted_val = "[Encrypted - No Master Key]"
                    if master_key and enc_val:
                        decrypted_val = decrypt_aes_gcm(enc_val, master_key)
                        
                    results['cookies'].append({
                        'timestamp': webkit_timestamp_to_iso(row[0]),
                        'host': row[1] or "",
                        'name': row[2] or "",
                        'value': decrypted_val,
                        'path': row[3] or "",
                        'expiry': webkit_timestamp_to_iso(row[4]) if row[4] > 0 else "Session Only",
                        'is_secure': bool(row[5]),
                        'is_httponly': bool(row[6]),
                        'browser': f"{browser_name} ({profile_name})",
                        'source': 'Cookie'
                    })
            except Exception as e:
                print(f"Error parsing Cookies for {browser_name}: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 4. Parse Autofill (Web Data)
        if web_data_temp and os.path.exists(web_data_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{web_data_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                # Check tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='autofill'")
                if cursor.fetchone():
                    cursor.execute("""
                        SELECT name, value, date_created, date_last_used, count
                        FROM autofill
                        ORDER BY date_last_used DESC
                    """)
                    for row in cursor.fetchall():
                        results['autofill'].append({
                            'timestamp': webkit_timestamp_to_iso(row[3]),
                            'field_name': row[0] or "",
                            'value': row[1] or "",
                            'count': row[4] or 0,
                            'browser': f"{browser_name} ({profile_name})",
                            'source': 'Autofill'
                        })
            except Exception as e:
                print(f"Error parsing Autofill for {browser_name}: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 5. Parse Logins (Login Data)
        if logins_temp and os.path.exists(logins_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{logins_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT origin_url, action_url, username_element, username_value, password_element, password_value, date_created, date_last_used
                    FROM logins
                """)
                for row in cursor.fetchall():
                    enc_pass = row[5]
                    decrypted_pass = "[Encrypted - No Master Key]"
                    if master_key and enc_pass:
                        decrypted_pass = decrypt_aes_gcm(enc_pass, master_key)
                        
                    results['logins'].append({
                        'timestamp': webkit_timestamp_to_iso(row[7]) or webkit_timestamp_to_iso(row[6]),
                        'origin_url': row[0] or "",
                        'action_url': row[1] or "",
                        'username_element': row[2] or "",
                        'username_value': row[3] or "",
                        'password_element': row[4] or "",
                        'password_value': decrypted_pass,
                        'browser': f"{browser_name} ({profile_name})",
                        'source': 'Login'
                    })
            except Exception as e:
                print(f"Error parsing Logins for {browser_name}: {e}")
            finally:
                if conn:
                    conn.close()
                
        return results

    def parse_firefox(self, profiles_root: str, profile_name: str) -> dict:
        """Parses Firefox places (History/Downloads), cookies, autofill, and logins json."""
        profile_path = os.path.join(profiles_root, profile_name)
        results = {
            'history': [],
            'downloads': [],
            'cookies': [],
            'autofill': [],
            'logins': [],
            'deleted_gaps': 0
        }
        
        # Check files
        places_src = os.path.join(profile_path, 'places.sqlite')
        cookies_src = os.path.join(profile_path, 'cookies.sqlite')
        formhist_src = os.path.join(profile_path, 'formhistory.sqlite')
        logins_src = os.path.join(profile_path, 'logins.json')
        
        # Copy to temp
        places_temp = copy_db_file(places_src, self.temp_dir)
        cookies_temp = copy_db_file(cookies_src, self.temp_dir)
        formhist_temp = copy_db_file(formhist_src, self.temp_dir)
        
        # 1. Parse History & Detect Gaps
        if places_temp and os.path.exists(places_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{places_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                
                # Query history visits
                cursor.execute("""
                    SELECT v.id, p.url, p.title, v.visit_date, p.visit_count, p.typed
                    FROM moz_historyvisits v
                    JOIN moz_places p ON v.place_id = p.id
                    ORDER BY v.visit_date DESC
                """)
                for row in cursor.fetchall():
                    results['history'].append({
                        'timestamp': firefox_timestamp_to_iso(row[3]),
                        'url': row[1] or "",
                        'title': row[2] or "",
                        'visit_duration': 0, # Firefox history visits table doesn't have standard duration
                        'visit_count': row[4] or 0,
                        'typed_count': 1 if row[5] else 0,
                        'browser': f"Firefox ({profile_name})",
                        'source': 'History'
                    })
                
                # Check for deleted entry ID gaps in moz_places
                cursor.execute("SELECT id FROM moz_places ORDER BY id")
                places_ids = [r[0] for r in cursor.fetchall()]
                if places_ids:
                    gaps = 0
                    for idx in range(1, len(places_ids)):
                        diff = places_ids[idx] - places_ids[idx-1]
                        if diff > 1:
                            gaps += (diff - 1)
                    results['deleted_gaps'] = gaps
            except Exception as e:
                print(f"Error parsing Firefox History: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 2. Parse Downloads from moz_annos
        if places_temp and os.path.exists(places_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{places_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                # Query annotations for downloads
                cursor.execute("""
                    SELECT p.url, a.content, a.dateAdded
                    FROM moz_annos a
                    JOIN moz_places p ON a.place_id = p.id
                    JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id
                    WHERE attr.name = 'downloads/destinationFileURI'
                    ORDER BY a.dateAdded DESC
                """)
                for row in cursor.fetchall():
                    target_uri = row[1] or ""
                    # file:///C:/path/file.ext -> C:\path\file.ext
                    clean_path = target_uri.replace("file:///", "").replace("/", "\\")
                    # URL unescape
                    import urllib.parse
                    clean_path = urllib.parse.unquote(clean_path)
                    filename = os.path.basename(clean_path) if clean_path else "Unknown"
                    
                    results['downloads'].append({
                        'timestamp': firefox_timestamp_to_iso(row[2]),
                        'file_name': filename,
                        'target_path': clean_path,
                        'received_bytes': 0, # not easily available in places.sqlite
                        'total_bytes': 0,
                        'state': 'Completed', # annotation generally signals completion
                        'referrer': '',
                        'site_url': row[0] or "",
                        'browser': f"Firefox ({profile_name})",
                        'source': 'Download'
                    })
            except Exception as e:
                print(f"Error parsing Firefox Downloads: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 3. Parse Cookies
        if cookies_temp and os.path.exists(cookies_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{cookies_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT creationTime, host, name, path, expiry, isSecure, isHttpOnly, lastAccessed, value
                    FROM moz_cookies
                    ORDER BY creationTime DESC
                """)
                for row in cursor.fetchall():
                    results['cookies'].append({
                        'timestamp': firefox_timestamp_to_iso(row[0]),
                        'host': row[1] or "",
                        'name': row[2] or "",
                        'value': row[8] or "", # Plaintext in Firefox!
                        'path': row[3] or "",
                        'expiry': unix_timestamp_to_iso(row[4]) if row[4] > 0 else "Session Only",
                        'is_secure': bool(row[5]),
                        'is_httponly': bool(row[6]),
                        'browser': f"Firefox ({profile_name})",
                        'source': 'Cookie'
                    })
            except Exception as e:
                print(f"Error parsing Firefox Cookies: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 4. Parse Autofill
        if formhist_temp and os.path.exists(formhist_temp):
            conn = None
            try:
                conn = sqlite3.connect(f"file:{formhist_temp}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT fieldname, value, firstUsed, lastUsed, timesUsed
                    FROM moz_formhistory
                    ORDER BY lastUsed DESC
                """)
                for row in cursor.fetchall():
                    results['autofill'].append({
                        'timestamp': firefox_timestamp_to_iso(row[3]),
                        'field_name': row[0] or "",
                        'value': row[1] or "",
                        'count': row[4] or 0,
                        'browser': f"Firefox ({profile_name})",
                        'source': 'Autofill'
                    })
            except Exception as e:
                print(f"Error parsing Firefox Autofill: {e}")
            finally:
                if conn:
                    conn.close()
                
        # 5. Parse Logins from logins.json
        if os.path.exists(logins_src):
            try:
                # Copy to temp first to preserve integrity
                logins_temp_path = os.path.join(self.temp_dir, f"{profile_name}_logins.json")
                import shutil
                shutil.copy2(logins_src, logins_temp_path)
                
                with open(logins_temp_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for record in data.get('logins', []):
                    # In Firefox, credentials are encrypted in NSS db (key4.db + logins.json)
                    # We report the metadata since pure-python nss decrypt is extremely complex
                    results['logins'].append({
                        'timestamp': unix_timestamp_to_iso(record.get('timeLastUsed', 0) // 1000) or unix_timestamp_to_iso(record.get('timeCreated', 0) // 1000),
                        'origin_url': record.get('hostname', ''),
                        'action_url': record.get('formSubmitURL', ''),
                        'username_element': record.get('usernameField', ''),
                        'username_value': "[Encrypted in Firefox NSS database]",
                        'password_element': record.get('passwordField', ''),
                        'password_value': "[Encrypted in Firefox NSS database]",
                        'browser': f"Firefox ({profile_name})",
                        'source': 'Login'
                    })
            except Exception as e:
                print(f"Error parsing Firefox logins.json: {e}")
                
        return results

    def run_extraction(self) -> dict:
        """Executes extraction for Chrome, Edge, and Firefox profiles. Returns consolidated structures."""
        all_data = {}
        
        # 1. Chrome
        chrome_root = self.get_chrome_path()
        if os.path.exists(chrome_root):
            profiles = self.scan_chrome_edge_profiles(chrome_root)
            for profile in profiles:
                try:
                    profile_data = self.parse_chrome_edge("Chrome", chrome_root, profile)
                    all_data[f"Chrome ({profile})"] = profile_data
                except Exception as e:
                    print(f"Failed extraction for Chrome profile {profile}: {e}")
                    
        # 2. Edge
        edge_root = self.get_edge_path()
        if os.path.exists(edge_root):
            profiles = self.scan_chrome_edge_profiles(edge_root)
            for profile in profiles:
                try:
                    profile_data = self.parse_chrome_edge("Edge", edge_root, profile)
                    all_data[f"Edge ({profile})"] = profile_data
                except Exception as e:
                    print(f"Failed extraction for Edge profile {profile}: {e}")
                    
        # 3. Firefox
        firefox_root = self.get_firefox_path()
        if os.path.exists(firefox_root):
            profiles = self.scan_firefox_profiles(firefox_root)
            for profile in profiles:
                try:
                    profile_data = self.parse_firefox(firefox_root, profile)
                    all_data[f"Firefox ({profile})"] = profile_data
                except Exception as e:
                    print(f"Failed extraction for Firefox profile {profile}: {e}")
                    
        return all_data

def run_diagnostics(all_data: dict) -> list:
    """Runs forensic anomaly analysis on the extracted data structures."""
    anomalies = []
    
    # Heuristic 1: Suspicious Download Locations
    suspicious_dirs = [
        r'c:\windows', 
        r'c:\windows\system32',
        r'appdata\local\temp',
        r'appdata\roaming'
    ]
    
    for profile_name, data in all_data.items():
        # Heuristic 2: Deleted History entries based on ID gaps
        gaps = data.get('deleted_gaps', 0)
        if gaps > 0:
            anomalies.append({
                'severity': 'Medium',
                'category': 'Deleted History',
                'message': f"Detected approximately {gaps} deleted history records in {profile_name} based on database ID gaps.",
                'evidence': f"Gap count: {gaps}"
            })
            
        # Downloads check
        for dl in data.get('downloads', []):
            path = dl['target_path'].lower()
            filename = dl['file_name']
            for s_dir in suspicious_dirs:
                if s_dir in path:
                    anomalies.append({
                        'severity': 'High',
                        'category': 'Suspicious Download',
                        'message': f"File '{filename}' was downloaded to a highly unusual folder: '{dl['target_path']}' ({dl['browser']})",
                        'evidence': f"Target Path: {dl['target_path']}, URL: {dl.get('site_url')}"
                    })
                    break
                    
        # Heuristic 3: Cleared History Heuristic
        # If history entries are extremely low, but cookies or logins exist from days ago
        hist_count = len(data.get('history', []))
        cookies_count = len(data.get('cookies', []))
        logins_count = len(data.get('logins', []))
        
        if hist_count < 10 and (cookies_count > 10 or logins_count > 2):
            anomalies.append({
                'severity': 'High',
                'category': 'Potential Cleared History',
                'message': f"Browser profile {profile_name} shows active presence (Cookies: {cookies_count}, Logins: {logins_count}) but has almost no browse history ({hist_count} records). This strongly implies history was cleared recently.",
                'evidence': f"History entries: {hist_count}, Cookies: {cookies_count}"
            })
            
        # Heuristic 4: Incognito Activity / History gaps
        # Look for cookie timestamps that do not align with any history record.
        # We can extract all history timestamps and look for cookies created during "dead zones".
        if hist_count > 0 and cookies_count > 0:
            try:
                # Convert history timestamps to datetime objects
                hist_dts = []
                for h in data.get('history', []):
                    ts = h['timestamp']
                    if ts and 'UTC' in ts:
                        dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc)
                        hist_dts.append(dt)
                        
                # Check cookies
                orphan_cookies = 0
                for c in data.get('cookies', []):
                    cts = c['timestamp']
                    if cts and 'UTC' in cts:
                        cdt = datetime.strptime(cts, '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc)
                        # Check if any history visit exists within 15 minutes (900 seconds)
                        close_visit = False
                        for hdt in hist_dts:
                            if abs((cdt - hdt).total_seconds()) < 900:
                                close_visit = True
                                break
                        if not close_visit:
                            orphan_cookies += 1
                            
                # If a significant number of cookies are orphan (created when there is no history entry nearby)
                if orphan_cookies > 15:
                    anomalies.append({
                        'severity': 'Medium',
                        'category': 'Incognito or Deleted Activity',
                        'message': f"Detected {orphan_cookies} cookies in {profile_name} that were created with no matching history visits within 15 minutes. This suggests Incognito browsing session traces or selective history deletion.",
                        'evidence': f"Orphan cookies count: {orphan_cookies}"
                    })
            except Exception as e:
                print(f"Error executing Incognito alignment check for {profile_name}: {e}")
                
    return anomalies
