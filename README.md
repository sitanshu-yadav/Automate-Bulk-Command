# Automate-Bulk-Command

Automated bulk command execution and configuration management tool for network devices. This tool connects to multiple network devices (Juniper, Cisco XR, Extreme), executes predefined commands, applies regex-based pattern matching, and logs results to Google Sheets.

## 🎯 Features

- **Multi-Device Support**: Automatically detects and handles Juniper, Cisco XR, and Extreme network devices
- **Automated Device Detection**: Intelligently identifies device type via `show version` command
- **Regex Pattern Matching**: Executes regex rules to detect specific configurations or conditions
- **Conditional Actions**: Runs follow-up commands based on pattern matches
- **Interactive Prompt Handling**: Automatically responds to device prompts (yes/no confirmations)
- **Secure Password Management**: Uses OpenSSL AES-256-CBC encryption for password storage
- **Google Sheets Integration**: Logs all execution results with timestamps to Google Sheets
- **SSH Connection Management**: Uses Paramiko for secure SSH connections with timeout handling
- **Live Command Output**: Streams command output in real-time with paging support

## 📋 Prerequisites

- Python 3.6+
- Network access to devices
- Google Sheets API credentials (JSON file)
- Encrypted password file (AES-256-CBC format)
- Required Python packages:
  - `paramiko` - SSH protocol implementation
  - `pyyaml` - YAML configuration file parsing
  - `gspread` - Google Sheets API client
  - `google-auth-oauthlib` - Google OAuth2 authentication

### Installation

```bash
pip install paramiko pyyaml gspread google-auth-oauthlib google-auth-httplib2
```

## 📁 Configuration Files

### 1. `devices.yaml`
Device inventory configuration. List all target devices here.

**Example:**
```yaml
devices:
  - hostname: 192.168.1.10
  - hostname: device.example.com
  - hostname: 192.168.1.20
```

### 2. `regex_rules.yaml`
Defines regex patterns, checks, and follow-up actions for each device type.

**Structure:**
```yaml
juniper:
  - check_cmd: "show interfaces terse"
    pattern: "down"
    description: "Interface down detected"
    action_cmds:
      - "request system reboot"

cisco_xr:
  - check_cmd: "show interfaces brief"
    pattern: "Down|administratively down"
    description: "Interface problem detected"
    action_cmds:
      - "interface GigabitEthernet0/0/0/0"
      - "no shutdown"

extreme:
  - check_cmd: "show port"
    pattern: "NotReady"
    description: "Port not ready"
    action_cmds: []
```

**Fields:**
- `check_cmd`: Command to execute on device
- `pattern`: Regex pattern to match in command output
- `description`: Human-readable description of the condition
- `action_cmds`: List of commands to execute if pattern matches

### 3. `interactive_prompts.yaml`
Defines patterns and automatic responses for device prompts.

**Example:**
```yaml
prompts:
  - pattern: "overwrite it\\?\\s*\\(y/N\\)"
    response: "y"
  - pattern: "Do you want to continue\\?\\s*\\(y/n\\)"
    response: "y"
  - pattern: "Password:"
    response: "your_password"
```

## 🔒 Security Setup

### 1. Encrypt Password
Use OpenSSL to encrypt your device password:

```bash
openssl enc -aes-256-cbc -pbkdf2 -in plaintext_password.txt -out password.enc
```

You'll be prompted to enter a passphrase. Remember this for the script.

### 2. Google Sheets API Setup

1. Create a Google Cloud Project
2. Enable Google Sheets API and Google Drive API
3. Create a Service Account and download JSON key file
4. Share your Google Sheet with the service account email
5. Update the JSON file path in `main.py`:

```python
creds = Credentials.from_service_account_file(
    "path/to/your/service_account.json", scopes=scopes
)
```

## 🚀 Usage

### Configuration

Update `main.py` with your credentials:

```python
def main():
    username = "your_username"
    enc_file = 'path/to/password.enc'
    passphrase = "your_passphrase"
    # ... rest of configuration
```

### Running the Script

```bash
python main.py
```

### Execution Flow

1. **Decrypt Password**: Uses OpenSSL to decrypt the password
2. **Load Configuration**: Reads devices, regex rules, and interactive prompts
3. **Initialize Google Sheet**: Creates headers if sheet is empty
4. **Connect to Devices**: For each device in inventory:
   - Establish SSH connection
   - Auto-detect device type
   - Set device-specific configurations (screen length, paging, etc.)
   - Apply regex rules
   - Log results to Google Sheets
   - Disconnect

## 📊 Google Sheets Output

The script logs results with the following columns:

| Timestamp | Device | Device_Type | Check_Command | Regex | Result | Follow_Up_Commands |
|-----------|--------|-------------|---------------|-------|--------|-------------------|
| 2025-12-28 10:30:45 | 192.168.1.10 | JUNIPER | show interfaces terse | down | MATCH | request system reboot |

**Result Values:**
- `MATCH` - Pattern found in output; follow-up commands executed
- `NO_MATCH` - Pattern not found in output

## 🔧 Device Handler Functions

### Juniper (`handle_juniper`)
- Sets screen length to 0 (disables paging)
- Sets screen width to 0
- Applies juniper-specific regex rules
- Executes `show system uptime` for verification

### Cisco XR (`handle_cisco`)
- Sets terminal length to 0 (disables paging)
- Applies cisco_xr-specific regex rules
- Executes `show version brief` for verification

### Extreme (`handle_extreme`)
- Disables CLI paging
- Applies extreme-specific regex rules
- Executes `show switch` for verification

## 🛠️ Main Functions

| Function | Purpose |
|----------|---------|
| `decrypt_password_openssl()` | Decrypts AES-256-CBC encrypted password |
| `connect_device()` | Establishes SSH connection with timeout |
| `clear_buffer()` | Clears SSH shell buffer |
| `load_regex_rules()` | Loads regex rules from YAML |
| `load_interactive_prompts()` | Loads interactive prompt handlers from YAML |
| `apply_regex_rules()` | Executes regex matching and follow-up actions |
| `run_live_command()` | Executes command on device with live output |
| `detect_device_type()` | Identifies device OS type |
| `init_google_sheet()` | Initializes Google Sheets logging |
| `log_to_sheet()` | Logs execution results to Google Sheets |

## ⚠️ Error Handling

- SSH connection timeout: 10 seconds
- Command execution timeout: 30 seconds
- Failed connections are logged with error messages
- Script continues to next device on failure
- OpenSSL decryption errors terminate the script

## 📝 Example Workflow

```
1. User runs: python main.py
2. Script decrypts password from encrypted file
3. Loads devices from inventory
4. For each device:
   a. Connects via SSH
   b. Detects OS type (Juniper/Cisco/Extreme)
   c. Runs device-specific configuration (disable paging)
   d. Executes regex rules:
      - Runs check command
      - Evaluates output against regex pattern
      - Executes follow-up commands if matched
      - Logs results
   e. Disconnects
5. All results available in Google Sheet
```

## 🐛 Troubleshooting

**SSH Connection Failed**
- Verify device IP/hostname is reachable
- Check username and password are correct
- Ensure SSH is enabled on device

**OpenSSL Error**
- Verify encrypted password file exists
- Check passphrase is correct
- Ensure openssl is installed: `apt-get install openssl`

**Google Sheets Error**
- Verify service account JSON path is correct
- Confirm sheet is shared with service account email
- Check Google Sheets API is enabled in GCP

**Regex Not Matching**
- Test regex pattern separately
- Check `re.IGNORECASE` flag behavior
- Verify command output format matches expected pattern



## 👤 Author

[Sitanshu]
