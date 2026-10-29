import os
import sys
import json
import time
import base64
import ctypes
from ctypes import wintypes
import subprocess

# --- Windows Credential API Setup ---
class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]

PCREDENTIAL = ctypes.POINTER(CREDENTIAL)
advapi32 = ctypes.windll.advapi32

CredReadW = advapi32.CredReadW
CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIAL)]
CredReadW.restype = wintypes.BOOL

CredWriteW = advapi32.CredWriteW
CredWriteW.argtypes = [PCREDENTIAL, wintypes.DWORD]
CredWriteW.restype = wintypes.BOOL

CredDeleteW = advapi32.CredDeleteW
CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
CredDeleteW.restype = wintypes.BOOL

CredFree = advapi32.CredFree
CredFree.argtypes = [ctypes.c_void_p]

CRED_TARGET = "gemini:antigravity"

def cred_read():
    """Read the current raw token and username from Windows Credential Manager."""
    pCred = PCREDENTIAL()
    if CredReadW(CRED_TARGET, 1, 0, ctypes.byref(pCred)):
        cred = pCred.contents
        raw_bytes = bytes(cred.CredentialBlob[:cred.CredentialBlobSize])
        user = cred.UserName
        CredFree(pCred)
        return raw_bytes, user
    return None, None

def cred_write(raw_bytes, username="antigravity"):
    """Write token bytes to Windows Credential Manager."""
    cred = CREDENTIAL()
    cred.Type = 1  # CRED_TYPE_GENERIC
    cred.TargetName = CRED_TARGET
    cred.UserName = username
    cred.CredentialBlobSize = len(raw_bytes)
    
    blob_buffer = (ctypes.c_byte * len(raw_bytes))(*raw_bytes)
    cred.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(ctypes.c_byte))
    cred.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
    
    res = CredWriteW(ctypes.byref(cred), 0)
    if not res:
        err = ctypes.GetLastError()
        raise OSError(f"CredWriteW failed with error: {err}")
    return True

def cred_delete():
    """Delete the credential from Windows Credential Manager."""
    CredDeleteW(CRED_TARGET, 1, 0)

def extract_email_from_token(raw_bytes):
    """Extract email address from the id_token JWT or id_token_email."""
    try:
        data = json.loads(raw_bytes.decode('utf-8'))
        # 1. New Antigravity format: direct email field
        if 'id_token_email' in data and data['id_token_email']:
            return data['id_token_email']
        if 'email' in data and data['email']:
            return data['email']
        # 2. Legacy format: decode JWT id_token
        id_token = data.get('id_token', '')
        if id_token and '.' in id_token:
            payload_b64 = id_token.split('.')[1]
            padded = payload_b64 + '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            return payload.get('email', '')
    except Exception:
        pass
    return ''

# --- Paths and Directories ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE_DIR, "state.inc")
LOG_FILE = os.path.join(BASE_DIR, "switcher_debug.log")
VAULT_DIR = os.path.join(BASE_DIR, "vault")
ACTIVE_SLOT_FILE = os.path.join(VAULT_DIR, "active_slot.txt")
CREATE_NO_WINDOW = 0x08000000

os.makedirs(VAULT_DIR, exist_ok=True)

def debug_log(msg):
    try:
        import datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{now}] {msg}\n")
    except Exception:
        pass

def find_antigravity_exe():
    """Locate Antigravity executable across common installation paths."""
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\antigravity\Antigravity.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\Antigravity\Antigravity.exe"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\Antigravity\Antigravity.exe"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]

ANTIGRAVITY_EXE = find_antigravity_exe()
APP_STORAGE = os.path.expandvars(r"%APPDATA%\Antigravity\app_storage.json")

def get_snapshot():
    """Return dictionary of {pid: (name, parent_pid)} and list of visible window titles."""
    procs = {}
    windows = []
    try:
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.wintypes.DWORD),
                ('cntUsage', ctypes.wintypes.DWORD),
                ('th32ProcessID', ctypes.wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.wintypes.ULONG)),
                ('th32ModuleID', ctypes.wintypes.DWORD),
                ('cntThreads', ctypes.wintypes.DWORD),
                ('th32ParentProcessID', ctypes.wintypes.DWORD),
                ('pcPriClassBase', ctypes.wintypes.LONG),
                ('dwFlags', ctypes.wintypes.DWORD),
                ('szExeFile', ctypes.c_char * 260)
            ]
        h = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if ctypes.windll.kernel32.Process32First(h, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.decode('ansi', errors='ignore')
                procs[pe.th32ProcessID] = (name, pe.th32ParentProcessID)
                if not ctypes.windll.kernel32.Process32Next(h, ctypes.byref(pe)):
                    break
        ctypes.windll.kernel32.CloseHandle(h)
    except Exception as e:
        debug_log(f"Error in get_snapshot procs: {e}")

    try:
        user32 = ctypes.windll.user32
        def callback(hwnd, extra):
            if user32.IsWindowVisible(hwnd):
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value.strip()
                    if title:
                        pid = ctypes.wintypes.DWORD()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        windows.append((pid.value, title))
            return True
        CB = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        user32.EnumWindows(CB(callback), 0)
    except Exception as e:
        debug_log(f"Error in get_snapshot windows: {e}")

    return procs, windows

def get_active_slot():
    """Get the currently active slot number (1-4)."""
    if os.path.exists(ACTIVE_SLOT_FILE):
        try:
            with open(ACTIVE_SLOT_FILE, "r", encoding="utf-8") as f:
                val = int(f.read().strip())
                if 1 <= val <= 4:
                    return val
        except Exception:
            pass
    return 1

def set_active_slot(slot):
    """Record which slot is currently active."""
    try:
        with open(ACTIVE_SLOT_FILE, "w", encoding="utf-8") as f:
            f.write(str(slot))
    except Exception:
        pass

def is_antigravity_running():
    """Check if Antigravity.exe is currently running."""
    try:
        cmd = ["tasklist", "/FI", "IMAGENAME eq Antigravity.exe", "/NH"]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        return "Antigravity.exe" in out
    except Exception:
        return False

def kill_antigravity():
    """Kill all Antigravity and language_server processes cleanly."""
    try:
        subprocess.run(["taskkill", "/F", "/IM", "Antigravity.exe", "/T"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["taskkill", "/F", "/IM", "language_server.exe", "/T"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass
    time.sleep(1.2)

def launch_antigravity():
    """Launch Antigravity normally."""
    exe_path = find_antigravity_exe()
    try:
        DETACHED = 0x00000008 | 0x00000200
        p = subprocess.Popen([exe_path], creationflags=DETACHED, close_fds=True)
        debug_log(f"Antigravity process started with PID: {p.pid} from {exe_path}")
    except Exception as e:
        import traceback
        debug_log(f"EXCEPTION in launch_antigravity: {e}\n{traceback.format_exc()}")

def update_app_storage_email(email):
    """Update lastLoginUsername in app_storage.json so UI reflects the account."""
    if not os.path.exists(APP_STORAGE):
        return
    try:
        with open(APP_STORAGE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["jetski.onboarding.lastLoginUsername"] = email
        with open(APP_STORAGE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def save_current_to_slot(slot):
    """Save the live Windows Credential into the vault for the given slot."""
    raw, user = cred_read()
    if not raw:
        return False

    slot_dir = os.path.join(VAULT_DIR, f"slot_{slot}")
    os.makedirs(slot_dir, exist_ok=True)
    
    token_file = os.path.join(slot_dir, "token.json")
    with open(token_file, "wb") as f:
        f.write(raw)
        
    email = extract_email_from_token(raw)
    meta = {
        "slot": slot,
        "email": email,
        "user": user or "antigravity",
        "updated_at": time.time()
    }
    meta_file = os.path.join(slot_dir, "meta.json")
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return True

def get_slot_vault_info(slot):
    """Read saved info for a slot from the vault."""
    slot_dir = os.path.join(VAULT_DIR, f"slot_{slot}")
    meta_file = os.path.join(slot_dir, "meta.json")
    token_file = os.path.join(slot_dir, "token.json")
    
    if os.path.exists(token_file):
        email = ""
        meta = {}
        if os.path.exists(meta_file):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    email = meta.get("email", "")
            except Exception:
                pass
        
        # If email was blank or missing, extract directly from existing token.json (safe read-only)
        if not email:
            try:
                with open(token_file, "rb") as f:
                    raw = f.read()
                email = extract_email_from_token(raw)
                if email:
                    meta["slot"] = slot
                    meta["email"] = email
                    if "user" not in meta:
                        meta["user"] = "antigravity"
                    meta["updated_at"] = time.time()
                    with open(meta_file, "w", encoding="utf-8") as f:
                        json.dump(meta, f, indent=2)
            except Exception:
                pass

        if email:
            return {"configured": True, "email": email}
        return {"configured": True, "email": f"Account {slot}"}
    return {"configured": False, "email": f"Empty Slot {slot} (Click to Setup)"}

def initialize_vault_if_needed():
    """If vault is empty, capture the currently active account as Slot 1."""
    slot1_token = os.path.join(VAULT_DIR, "slot_1", "token.json")
    if not os.path.exists(slot1_token):
        raw, _ = cred_read()
        if raw:
            save_current_to_slot(1)
            set_active_slot(1)

def sync_current_account():
    """Sync the live Windows Credential into whichever slot is active."""
    initialize_vault_if_needed()
    active_slot = get_active_slot()
    raw, _ = cred_read()
    if raw:
        save_current_to_slot(active_slot)

def switch_to_slot(target_slot):
    """Switch active account to target slot: save current, swap cred, restart app."""
    debug_log(f"==================================================")
    debug_log(f"ACTION: switch_to_slot({target_slot}) initiated")
    before_procs, before_wins = get_snapshot()

    try:
        if not (1 <= target_slot <= 4):
            debug_log(f"Invalid target slot: {target_slot}")
            return

        initialize_vault_if_needed()
        current_slot = get_active_slot()
        debug_log(f"Current slot: {current_slot} -> Target: {target_slot}")
        
        # 1. Capture current live session to the current slot
        res_save = save_current_to_slot(current_slot)
        debug_log(f"save_current_to_slot({current_slot}): {res_save}")
        
        # 2. Kill Antigravity processes
        if is_antigravity_running():
            debug_log("Antigravity is currently running. Calling kill_antigravity()...")
            kill_antigravity()
            debug_log("kill_antigravity() completed.")
        else:
            debug_log("Antigravity was not running.")
            
        # 3. Swap the credentials
        target_token_file = os.path.join(VAULT_DIR, f"slot_{target_slot}", "token.json")
        if os.path.exists(target_token_file):
            debug_log(f"Target token found at {target_token_file}. Writing to Windows Credential Manager...")
            with open(target_token_file, "rb") as f:
                raw = f.read()
            cred_write(raw, "antigravity")
            email = extract_email_from_token(raw)
            debug_log(f"Extracted email: {email}. Updating app_storage...")
            if email:
                update_app_storage_email(email)
        else:
            debug_log(f"No token found for slot {target_slot}. Deleting credential.")
            cred_delete()
            update_app_storage_email("")

        # 4. Set active slot
        set_active_slot(target_slot)
        debug_log(f"Active slot recorded as {target_slot}.")
        
        # 5. Launch Antigravity
        debug_log(f"Launching Antigravity via {ANTIGRAVITY_EXE}...")
        launch_antigravity()
        debug_log("launch_antigravity() finished.")
        
        # 6. Update Rainmeter state
        write_state()
        debug_log("switch_to_slot completed successfully.")
    except Exception as e:
        import traceback
        debug_log(f"ERROR in switch_to_slot: {e}\n{traceback.format_exc()}")

def restart_active_slot():
    """Cleanly restart Antigravity with the active slot."""
    active_slot = get_active_slot()
    if is_antigravity_running():
        kill_antigravity()
    
    token_file = os.path.join(VAULT_DIR, f"slot_{active_slot}", "token.json")
    if os.path.exists(token_file):
        with open(token_file, "rb") as f:
            raw = f.read()
        cred_write(raw, "antigravity")
        
    launch_antigravity()
    time.sleep(0.5)
    write_state()

def reset_slot(slot):
    """Reset a slot's saved credentials."""
    slot_dir = os.path.join(VAULT_DIR, f"slot_{slot}")
    if os.path.exists(slot_dir):
        import shutil
        shutil.rmtree(slot_dir, ignore_errors=True)
        
    active_slot = get_active_slot()
    if slot == active_slot:
        cred_delete()
        update_app_storage_email("")
        if is_antigravity_running():
            kill_antigravity()
            launch_antigravity()
            
    write_state()

def write_state():
    """Write state.inc for Rainmeter."""
    sync_current_account()
    active_slot = get_active_slot()
    is_running = is_antigravity_running()

    slots_info = {i: get_slot_vault_info(i) for i in range(1, 5)}

    if is_running:
        active_title = f"ACC {active_slot} ACTIVE"
        active_color = "100,230,120"
    else:
        active_title = f"ACC {active_slot} (CLOSED)"
        active_color = "200,200,200"

    lines = [
        "; Auto-generated by agy_agent.py (Account Vault Switcher)",
        "[Variables]",
        f"ActiveSlot={active_slot}",
        f"ActiveTitle=\"{active_title}\"",
        f"ActiveColor={active_color}",
        f"IsRunning={1 if is_running else 0}",
    ]

    for i in range(1, 5):
        info = slots_info[i]
        is_active = (i == active_slot)
        is_configured = info["configured"]
        email_str = info["email"]

        if is_active:
            row_border = "100,230,120,200"
            row_bg = "100,230,120,18"
            row_hover_bg = "100,230,120,35"
            row_hover_border = "100,230,120,255"
            row_num_color = "100,230,120"
            row_email_color = "255,255,255,255"
            row_status = "ACTIVE"
            row_status_color = "100,230,120"
            row_pill_border = "100,230,120,160"
            row_pill_bg = "100,230,120,30"
        elif is_configured:
            row_border = "255,255,255,40"
            row_bg = "0,0,0,60"
            row_hover_bg = "255,255,255,18"
            row_hover_border = "255,255,255,140"
            row_num_color = "255,255,255,230"
            row_email_color = "210,210,210,210"
            row_status = "LAUNCH"
            row_status_color = "210,210,210,180"
            row_pill_border = "255,255,255,50"
            row_pill_bg = "0,0,0,1"
        else:
            row_border = "255,255,255,20"
            row_bg = "0,0,0,30"
            row_hover_bg = "255,255,255,12"
            row_hover_border = "255,255,255,80"
            row_num_color = "140,140,140,130"
            row_email_color = "130,130,130,130"
            row_status = "+ SETUP"
            row_status_color = "140,140,140,150"
            row_pill_border = "255,255,255,25"
            row_pill_bg = "0,0,0,1"

        if is_configured:
            reset_text = "RESET"
            reset_border = "255,255,255,30"
            reset_color = "180,180,180,160"
            reset_hidden = "0"
        else:
            reset_text = ""
            reset_border = "0,0,0,0"
            reset_color = "0,0,0,0"
            reset_hidden = "1"

        lines.extend([
            f"Row{i}_Border={row_border}",
            f"Row{i}_Bg={row_bg}",
            f"Row{i}_HoverBg={row_hover_bg}",
            f"Row{i}_HoverBorder={row_hover_border}",
            f"Row{i}_NumColor={row_num_color}",
            f"Row{i}_EmailColor={row_email_color}",
            f"Row{i}_Email=\"{email_str}\"",
            f"Row{i}_Status=\"{row_status}\"",
            f"Row{i}_StatusColor={row_status_color}",
            f"Row{i}_PillBorder={row_pill_border}",
            f"Row{i}_PillBg={row_pill_bg}",
            f"Row{i}_ResetText=\"{reset_text}\"",
            f"Row{i}_ResetBorder={reset_border}",
            f"Row{i}_ResetColor={reset_color}",
            f"Row{i}_ResetHidden={reset_hidden}",
        ])

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        action = "status"
    else:
        action = sys.argv[1].lower()

    if action == "status":
        write_state()
    elif action == "switch" and len(sys.argv) >= 3:
        try:
            target_slot = int(sys.argv[2])
            switch_to_slot(target_slot)
        except ValueError:
            pass
    elif action == "restart":
        restart_active_slot()
    elif action == "reset" and len(sys.argv) >= 3:
        try:
            target_slot = int(sys.argv[2])
            reset_slot(target_slot)
        except ValueError:
            pass
    else:
        write_state()
