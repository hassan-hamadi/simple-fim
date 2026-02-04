
### The Template

# simple-fim

A lightweight File Integrity Monitor (FIM) written in Python.

## 📝 Description
**simple-fim** is a cybersecurity tool that establishes a baseline of files and monitors them for unauthorized changes. It calculates file hashes (SHA-256) and continuously compares them against the stored baseline to detect modifications, deletions, or new file creations.

This tool is designed for educational purposes to demonstrate the concepts of **integrity monitoring** and **hashing**.

## 🚀 Features
- [x] **Calculate Baseline:** Function to calculate SHA-256 hash of a specific target file.
- [x] **Monitor:** Continuous loop that checks the file every few seconds.
- [x] **Compare & Alert:** Print "File Modified!" to console if the hash changes.
- [x] **Directory Monitoring:** Recursively scan and monitor entire directories.
- [x] **Parallel Hashing:** Uses ThreadPoolExecutor for fast multi-file processing.
- [x] **Timestamped Logging:** Alerts logged to `integrity_log.txt`.
- [x] **Discord Alerts:** Push notifications via Discord webhook integration.
- [x] **Calculate Diff:** Detect exactly which lines were added, removed, or changed in modified text files.
- [x] **Detailed Alerts:** Include the diff output in terminal logs, log file entries, and Discord notifications.


## 🛠️ Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/hassan-hamadi/simple-fim.git
    ```
2.  Navigate to the directory:
    ```bash
    cd simple-fim
    ```

## 💻 Usage

Run the script with Python 3:

```bash
# Monitor a single file
python simple-fim.py -f <file_path>

# Monitor an entire directory
python simple-fim.py -d <directory_path>

# Specify a custom log file
python simple-fim.py -d <directory_path> -l /path/to/logfile.txt

# Enable Discord webhook alerts
python simple-fim.py -d <directory_path> -w <webhook_url>
```

### Options
| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path of a single file to monitor |
| `-d`, `--directory` | Path of a directory to monitor (recursive) |
| `-l`, `--log` | Path for log file (default: `~/.simple-fim/integrity_log.txt`) |
| `-w`, `--webhook` | Discord webhook URL for push notifications |

## 🗺️ Roadmap

### Phase 1: The MVP (Single File)
- [x] **Calculate Baseline:** Function to calculate SHA-256 hash of a specific target file.
- [x] **Monitor:** Continuous loop that checks the file every few seconds.
- [x] **Compare & Alert:** Print "File Modified!" to console if the hash changes.

### Phase 2: Directory & Alerting
- [x] **Watch a Directory:** Crawl an entire folder (recursively) and map every filename to its hash.
- [x] **User Interface:** Log alerts to a file (`integrity_log.txt`) with timestamps instead of just print statements.
- [x] **Alerting:** Integrate a Webhook (Discord/Slack) for push notifications.

### Phase 3: Diff & Forensics
- [x] **Calculate Diff:** Detect exactly which lines were added, removed, or changed in modified text files.
- [x] **Detailed Alerts:** Include the diff output in terminal logs, log file entries, and Discord notifications.

### Phase 4: 
- [ ] **Real-Time Monitoring:** Use `watchdog` to receive real-time filesystem events.
- [ ] **Noise Reduction:** Implement a '.fimignore' file to exclude certain files and directories from monitoring as an option.

## ⚠️ Limitations

- **Polling-Based Detection:** This tool uses a polling interval (default: 5 seconds) to check for file changes. If a file is modified and then reverted back to its original state before the next check, the change will **not** be detected.

- **No Kernel-Level Access:** Unlike enterprise FIM solutions that use kernel-level hooks (e.g., `inotify`, `fanotify`, or Windows ETW), this script does not receive real-time filesystem events. This means:
  - Rapid successive changes may be missed
  - The exact timestamp of a change is approximate (within the polling interval)
  - Higher polling frequency increases CPU usage

- **Binary File Diffs:** Binary files (images, executables, etc.) are detected as modified via hash comparison, but no diff output is provided since binary diffs are not human-readable.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

