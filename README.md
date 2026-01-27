
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
python main.py -f <file_name>
```

## 🗺️ Roadmap

### Phase 1: The MVP (Single File)
- [x] **Calculate Baseline:** Function to calculate SHA-256 hash of a specific target file.
- [x] **Monitor:** Continuous loop that checks the file every few seconds.
- [x] **Compare & Alert:** Print "File Modified!" to console if the hash changes.

### Phase 2: irectory & Alerting
- [ ] **Watch a Directory:** Crawl an entire folder (recursively) and map every filename to its hash.
- [ ] **User Interface:** Log alerts to a file (`integrity_log.txt`) with timestamps instead of just print statements.
- [ ] **Alerting:** Integrate a Webhook (Discord/Slack) for push notifications.

### Phase 3: Cloud & Forensics
- [ ] **Cloud Sync:** Upload logs to a cloud database (Firebase/AWS).
- [ ] **Email Extraction:** Calculate the "diff" (lines added/removed) of text files and email the changes.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

