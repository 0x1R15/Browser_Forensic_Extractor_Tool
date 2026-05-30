import os
import sys
from datetime import datetime

# Ensure root package is in Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browser_forensics.parsers import BrowserParser, run_diagnostics
from browser_forensics.reports import export_json, export_csv, generate_pdf_report

def get_mtimes(parser):
    """Gathers last modification times of all active original browser files."""
    mtimes = {}
    
    # Chrome Default
    chrome_root = parser.get_chrome_path()
    if os.path.exists(chrome_root):
        for profile in parser.scan_chrome_edge_profiles(chrome_root):
            p_path = os.path.join(chrome_root, profile)
            for db in ['History', 'Cookies', 'Web Data', 'Login Data']:
                path = os.path.join(p_path, db)
                if os.path.exists(path):
                    mtimes[f"Chrome_{profile}_{db}"] = (path, os.path.getmtime(path))
                    
    # Edge Default
    edge_root = parser.get_edge_path()
    if os.path.exists(edge_root):
        for profile in parser.scan_chrome_edge_profiles(edge_root):
            p_path = os.path.join(edge_root, profile)
            for db in ['History', 'Cookies', 'Web Data', 'Login Data']:
                path = os.path.join(p_path, db)
                if os.path.exists(path):
                    mtimes[f"Edge_{profile}_{db}"] = (path, os.path.getmtime(path))
                    
    # Firefox
    firefox_root = parser.get_firefox_path()
    if os.path.exists(firefox_root):
        for profile in parser.scan_firefox_profiles(firefox_root):
            p_path = os.path.join(firefox_root, profile)
            for db in ['places.sqlite', 'cookies.sqlite', 'formhistory.sqlite', 'logins.json']:
                path = os.path.join(p_path, db)
                if os.path.exists(path):
                    mtimes[f"Firefox_{profile}_{db}"] = (path, os.path.getmtime(path))
                    
    return mtimes

def main():
    print("==================================================")
    print("  BROWSER FORENSIC EXTRACTOR - VALIDATION TEST")
    print("==================================================")
    
    # Initialize parser
    workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    temp_dir = os.path.join(workspace_dir, "temp_extraction_test")
    parser = BrowserParser(temp_dir)
    
    print("\n[Step 1] Gathering original browser database timestamps...")
    pre_mtimes = get_mtimes(parser)
    print(f"Tracked {len(pre_mtimes)} source files.")
    
    print("\n[Step 2] Executing data extraction and decryption...")
    start_time = datetime.now()
    extracted_data = parser.run_extraction()
    duration = (datetime.now() - start_time).total_seconds()
    print(f"Acquisition completed in {duration:.2f} seconds.")
    
    # Print stats
    print("\nExtraction Stats:")
    for profile, data in extracted_data.items():
        print(f"Profile: {profile}")
        print(f"  History visits: {len(data.get('history', []))}")
        print(f"  Downloads:      {len(data.get('downloads', []))}")
        print(f"  Cookies:        {len(data.get('cookies', []))}")
        print(f"  Autofill keys:  {len(data.get('autofill', []))}")
        print(f"  Logins found:   {len(data.get('logins', []))}")
        
    print("\n[Step 3] Running Forensic Heuristics & Diagnostics...")
    anomalies = run_diagnostics(extracted_data)
    print(f"Flagged {len(anomalies)} anomalies/flags:")
    for a in anomalies:
        print(f"  [{a['severity']}] {a['category']}: {a['message']}")
        
    print("\n[Step 4] Checking file integrity (Forensic Soundness)...")
    post_mtimes = get_mtimes(parser)
    
    integrity_failed = False
    for key, (path, pre_mtime) in pre_mtimes.items():
        post_mtime = post_mtimes.get(key, (None, None))[1]
        if post_mtime != pre_mtime:
            print(f"  [ALERT] Original file modified! {path}")
            integrity_failed = True
            
    if not integrity_failed:
        print("  [SUCCESS] All original browser database timestamps match exactly!")
        print("  Forensic Integrity: VERIFIED (Read-Only sound).")
    else:
        print("  [ERROR] Forensic integrity compromised. Some original files were altered.")
        
    print("\n[Step 5] Testing report generation (JSON, CSV, PDF)...")
    case_meta = {
        "case_id": "INV-TEST-999",
        "suspect_name": "Test Subject",
        "device_name": "TEST-DEVICE-PC",
        "investigator": "Test Lead",
        "notes": "This is a diagnostic narrative note written for verification tests."
    }
    
    json_path = os.path.join(workspace_dir, "test_report.json")
    csv_path = os.path.join(workspace_dir, "test_timeline.csv")
    pdf_path = os.path.join(workspace_dir, "test_report.pdf")
    
    try:
        export_json(extracted_data, anomalies, case_meta, json_path)
        print(f"  JSON Report exported: {json_path}")
        
        export_csv(extracted_data, csv_path)
        print(f"  CSV Timeline exported: {csv_path}")
        
        generate_pdf_report(extracted_data, anomalies, case_meta, pdf_path)
        print(f"  PDF Document exported:  {pdf_path}")
        print("  [SUCCESS] All exports compiled successfully!")
    except Exception as e:
        print(f"  [ERROR] Export generation failed: {e}")
        import traceback
        traceback.print_exc()
        
    # Clean up temp
    print("\n[Step 6] Cleaning up test temp files...")
    if os.path.exists(temp_dir):
        import shutil
        shutil.rmtree(temp_dir)
        print("  Temp folder removed.")
        
    print("\nVerification Test Finished.")

if __name__ == "__main__":
    main()
