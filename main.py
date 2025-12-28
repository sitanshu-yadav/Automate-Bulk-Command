import paramiko
import time
import yaml
import socket
import subprocess
import sys
import re
import gspread
from google.oauth2.service_account import Credentials                                            
from datetime import datetime                                                                    
                                                                                                 
                                                                                                 
# -------------------------------                                                                
# PASSWORD DECRYPTION                                                                            
# -------------------------------                                                                
                                                                                                 
def decrypt_password_openssl(enc_file, passphrase):                                              
    try:                                                                                         
        result = subprocess.run(                                                                 
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-d",                                  
             "-in", enc_file, "-pass", f"pass:{passphrase}"],                                    
            stdout=subprocess.PIPE,                                                              
            stderr=subprocess.PIPE,
            check=True
        )
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print(f"\n \n [✗] OpenSSL error: {e.stderr.decode().strip()}")
        sys.exit(1)

# -------------------------------
# SSH CONNECT
# -------------------------------

def connect_device(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10
        )
        shell = ssh.invoke_shell()
        time.sleep(2)
        clear_buffer(shell)
        return ssh, shell
    except Exception as e:
        raise RuntimeError(f"SSH connection failed: {e}")

# -------------------------------
# CLEAR BUFFER
# -------------------------------

def clear_buffer(shell):
    while shell.recv_ready():
        shell.recv(65535)

# -------------------------------
# LOAD REGEX RULES
# -------------------------------

def load_regex_rules():
    with open("regex_rules.yaml") as f:
        return yaml.safe_load(f)

# -------------------------------
# LOAD INTERACTIVE PROMPT
# -------------------------------


def load_interactive_prompts():
    with open("interactive_prompts.yaml") as f:
        return yaml.safe_load(f)["prompts"]


# -------------------------------
# APPLY REGEX RULES
# -------------------------------

def apply_regex_rules(shell, device_type, regex_rules, sheet, device_name,interactive_prompts):

    # Prevent duplicate logging for same device & rule in a single run
    executed_rules = set()

    rules = regex_rules.get(device_type, [])
    if not rules:
        return

    for rule in rules:
        rule_id = f"{device_name}:{device_type}:{rule['check_cmd']}:{rule['pattern']}"

        # Skip if already executed (safety guard)
        if rule_id in executed_rules:
            continue

        # Run the check command
        print(f"\n▶ {rule['check_cmd']}")
        output = run_live_command(shell, rule["check_cmd"], interactive_prompts)

        # Regex evaluation
        if re.search(rule["pattern"], output, re.IGNORECASE):
            print(f"\n \n  ⚠ {rule.get('description', 'Condition matched')}")

            # Run follow-up commands
            for cmd in rule.get("action_cmds", []):
                run_live_command(shell, cmd,interactive_prompts)

            # Log MATCH
            log_to_sheet(
                sheet=sheet,
                device=device_name,
                device_type=device_type,
                check_cmd=rule["check_cmd"],
                pattern=rule["pattern"],
                result="MATCH",
                actions=rule.get("action_cmds", [])
            )

        else:
            print("\n ✅ Condition not met")

            # Log NO_MATCH
            log_to_sheet(
                sheet=sheet,
                device=device_name,
                device_type=device_type,
                check_cmd=rule["check_cmd"],
                pattern=rule["pattern"],
                result="NO_MATCH",
                actions=[]
            )

        # Mark rule as executed
        executed_rules.add(rule_id)

# -------------------------------
# GOOGLE SHEET INITIALIZATION
# -------------------------------

def init_google_sheet(sheet_name):
    scopes = ["https://www.googleapis.com/auth/spreadsheets", 
              "https://www.googleapis.com/auth/drive"]
    creds = Credentials.from_service_account_file(
        "JSON FILE LOCATION", scopes=scopes
    )
    client = gspread.authorize(creds)
    sheet = client.open(sheet_name).sheet1
    #ADD HEADER IF SHEET IS EMPTY
    expected_header = [
        "Timestamp",
        "Device",
        "Device_Type",
        "Check_Command",
        "Regex",
        "Result",
        "Follow_Up_Commands"
    ] 
    #ALWAYS check first row explicitly
    first_row = sheet.row_values(1)

    if first_row != expected_header:
        # Insert header at top (do NOT append)
        sheet.insert_row(expected_header, 1)

    return sheet

# -------------------------------
# LIVE COMMAND EXECUTION
# -------------------------------

def run_live_command(shell, command, interactive_prompts, prompt_regex=r"[>#]", silent=False):
    if not silent:
        print(f"\n▶ {command}\n")

    shell.send(command + "\n")
    time.sleep(0.3)

    output = ""
    start_time = time.time()

    while True:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode(errors="ignore")
            output += chunk

            # Handle paging automatically
            if "---(more" in chunk.lower() or "press <space>" in chunk.lower():
                shell.send(" ")
                time.sleep(0.1)
                continue

            # Handle interactive prompts (FROM YAML)
            for rule in interactive_prompts:
                if re.search(rule["pattern"], chunk, re.IGNORECASE):
                    response = rule["response"]
                    print(f"\n⚠ Interactive prompt detected → sending '{response}'")
                    shell.send(response + "\n")
                    time.sleep(0.3)

            # Print only if not silent
            if not silent:
                print(chunk, end="")

            # Prompt detected → command done
            if re.search(prompt_regex, chunk):
                break

        # Safety timeout
        if time.time() - start_time > 30:
            break

        time.sleep(0.2)

    return output

# -------------------------------
# DEVICE TYPE DETECTION
# -------------------------------

def detect_device_type(shell, interactive_prompts):
    output = run_live_command(shell, "show version", interactive_prompts, silent=True)

    out = output.lower()
    if "junos" in out:
        return "juniper"
    if "ios xr" in out:
        return "cisco_xr"
    if "extremexos" in out:
        return "extreme"

    return "unknown"

# -------------------------------
# JUNIPER HANDLER
# -------------------------------

def handle_juniper(shell,regex_rules,sheet,device_name, interactive_prompts):
    run_live_command(shell, "set cli screen-length 0", interactive_prompts)
    run_live_command(shell, "set cli screen-width 0", interactive_prompts)

    apply_regex_rules(shell, "juniper", regex_rules,sheet,device_name, interactive_prompts)
    run_live_command(shell, "show system uptime", interactive_prompts)

# -------------------------------
# CISCO XR HANDLER
# -------------------------------

def handle_cisco(shell,regex_rules,sheet,device_name, interactive_prompts):
    run_live_command(shell, "terminal length 0", interactive_prompts)

    apply_regex_rules(shell, "cisco_xr",regex_rules,sheet,device_name, interactive_prompts)
    run_live_command(shell, "show version brief", interactive_prompts)

# -------------------------------
# EXTREME HANDLER
# -------------------------------

def handle_extreme(shell,regex_rules,sheet,device_name, interactive_prompts):
    run_live_command(shell, "disable clipaging", interactive_prompts)
    
    apply_regex_rules(shell, "extreme",regex_rules,sheet,device_name, interactive_prompts)
    run_live_command(shell, "show switch", interactive_prompts)

# -------------------------------
# LOGGING FUNCTION
# -------------------------------

def log_to_sheet(sheet, device, device_type, check_cmd, pattern, result, actions):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sheet.append_row([
        timestamp,
        device,
        device_type.upper(),
        check_cmd,
        pattern,
        result,
        ", ".join(actions) if actions else "None"
    ])

# -------------------------------
# MAIN
# -------------------------------

def main():
    username = "username"
    enc_file = 'location of enc file to of password'
    passphrase = "Decrypt Password"

    password = decrypt_password_openssl(enc_file, passphrase)
    regex_rules = load_regex_rules()
    interactive_prompts = load_interactive_prompts()
    sheet = init_google_sheet("Automation-Execution-Log")
    with open("devices.yaml") as f:
        inventory = yaml.safe_load(f)

    for device in inventory["devices"]:
        host = device["hostname"]

        print("\n" + "=" * 60)
        print(f" 🔌 Connecting to {host}")
        print("=" * 60)

        try:
            ssh, shell = connect_device(host, username, password)

            device_type = detect_device_type(shell, interactive_prompts)
            print(f"\n🧠 Detected device type: {device_type.upper()}")

            if device_type == "juniper":
                handle_juniper(shell,regex_rules,sheet,host, interactive_prompts)
            elif device_type == "cisco_xr":
                handle_cisco(shell,regex_rules,sheet,host, interactive_prompts)
            elif device_type == "extreme":
                handle_extreme(shell,regex_rules,sheet,host, interactive_prompts)
            else:
                print("\n ❌ Unknown device type")

            ssh.close()
            print(f"\n 🔒 Disconnected from {host}")

        except Exception as e:
            print(f"\n ❌ Failed on {host}: {e}")

# -------------------------------------------------------------
if __name__ == "__main__":
    main()
