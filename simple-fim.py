#!/usr/bin/env python3

import hashlib
import argparse
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import difflib
from datetime import datetime, timezone

# Discord embed colors
COLOR_MODIFIED = 0xFF6B6B  # Red
COLOR_DELETED = 0xFFA500   # Orange
COLOR_NEW = 0x4CAF50       # Green

def send_discord_embed(title, file_path, webhook_url, color, diff_text=""):
    """Send a rich embed alert to Discord."""
    fields = [{"name": "📁 File", "value": f"`{file_path}`", "inline": False}]
    
    if diff_text:
        # Truncate diff if too long (Discord field limit is 1024 chars)
        truncated = diff_text[:900] + "\n..." if len(diff_text) > 900 else diff_text
        fields.append({"name": "📝 Changes", "value": f"```diff\n{truncated}\n```", "inline": False})
    
    data = {
        "embeds": [{
            "title": title,
            "color": color,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "Simple-FIM"}
        }]
    }
    try:
        response = requests.post(webhook_url, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending alert: {e}")


def is_binary(file_path):
    """Check if file is binary by looking for null bytes in first 8KB."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except IOError:
        return True  # Treat unreadable files as binary


def read_file_content(file_path):
    """Read file content, return None for binary files."""
    # Fast binary check first
    if is_binary(file_path):
        return None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except (UnicodeDecodeError, IOError):
        return None  # Fallback for edge cases


def calculate_diff(old_content, new_content, file_path):
    """Calculate the unified diff between old and new file content."""
    if old_content is None or new_content is None:
        return None  # Can't diff binary files
    
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    
    diff = difflib.unified_diff(old_lines, new_lines, lineterm='')
    return ''.join(diff)


def calculate_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Use 1MB buffer for better I/O performance
            for byte_block in iter(lambda: f.read(1048576), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {file_path}")
        sys.exit(1)

def process_file(file_path):
    """Calculate hash and read content for a file."""
    file_hash = calculate_hash(file_path)
    content = read_file_content(file_path)
    return {"hash": file_hash, "content": content}


def calculate_directory_map(target_folder):
    """Calculate the SHA256 hash and content of all files in a directory."""
    file_map = {}
    file_paths = []
    
    # Collect all file paths first
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            file_paths.append(os.path.join(root, file))
    
    # Process files in parallel using thread pool
    with ThreadPoolExecutor() as executor:
        future_to_path = {executor.submit(process_file, path): path for path in file_paths}
        
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                file_map[path] = future.result()
            except Exception as e:
                print(f"Error processing {path}: {e}")
    
    return file_map

def log_alert(event_type, file_path, log_path, webhook_url="", diff_text=""):
    """Log alert to terminal, file, and Discord."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    # Terminal output
    print(f"[{timestamp}] {event_type}: {file_path}")
    if diff_text:
        print(f"--- Diff ---\n{diff_text}\n------------")
    
    # Log file output
    with open(log_path, "a") as f:
        f.write(f"[{timestamp}] {event_type}: {file_path}\n")
        if diff_text:
            f.write(f"Diff:\n{diff_text}\n")
    
    # Discord embed
    if webhook_url:
        if event_type == "File modified":
            send_discord_embed("🚨 File Modified", file_path, webhook_url, COLOR_MODIFIED, diff_text)
        elif event_type == "File deleted":
            send_discord_embed("🗑️ File Deleted", file_path, webhook_url, COLOR_DELETED)
        elif event_type == "New file detected":
            send_discord_embed("✨ New File Detected", file_path, webhook_url, COLOR_NEW)

def main():
    # Default log path
    default_log_dir = os.path.expanduser("~/.simple-fim")
    default_log_path = os.path.join(default_log_dir, "integrity_log.txt")
    
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument("-f", "--file", required=False, help="Path of file to monitor")
    parser.add_argument("-d", "--directory", required=False, help="Path of directory to monitor")
    parser.add_argument("-l", "--log", required=False, default=default_log_path, 
                        help=f"Path for log file (default: {default_log_path})")
    parser.add_argument("-w", "--webhook", required=False, default="", 
                        help="Webhook URL for alerts")

    args = parser.parse_args()
    
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(args.log)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"Created log directory: {log_dir}")

    if not args.file and not args.directory:
        print("Please provide a file or directory to monitor")
        sys.exit(1)

    # File monitoring mode
    if args.file:
        baseline_hash = calculate_hash(args.file)
        baseline_content = read_file_content(args.file)
        print(f"File: {args.file}")
        print(f"Hash: {baseline_hash}")

        while True:
            time.sleep(5)
            current_hash = calculate_hash(args.file)
            if current_hash != baseline_hash:
                current_content = read_file_content(args.file)
                diff_text = calculate_diff(baseline_content, current_content, args.file) or ""
                
                print("File has been modified!")
                print(f"Baseline Hash: {baseline_hash}")
                print(f"Current Hash: {current_hash}")
                
                log_alert("File modified", args.file, args.log, args.webhook, diff_text)
                
                baseline_hash = current_hash
                baseline_content = current_content
                print(f"Baseline updated.")

    # Directory monitoring mode
    if args.directory:
        start_time = time.time()
        baseline_map = calculate_directory_map(args.directory)
        elapsed_time = time.time() - start_time
        
        print(f"Monitoring directory: {args.directory}")
        print(f"Tracking {len(baseline_map)} files")
        print(f"Initial scan took {elapsed_time:.2f} seconds")

        while True:
            time.sleep(5)
            current_map = calculate_directory_map(args.directory)
            
            # Check for modified or deleted files
            for file_path, baseline_data in baseline_map.items():
                if file_path not in current_map:
                    log_alert("File deleted", file_path, args.log, args.webhook)
                elif current_map[file_path]["hash"] != baseline_data["hash"]:
                    diff_text = calculate_diff(
                        baseline_data["content"],
                        current_map[file_path]["content"],
                        file_path
                    ) or ""
                    log_alert("File modified", file_path, args.log, args.webhook, diff_text)
            
            # Check for new files
            for file_path in current_map:
                if file_path not in baseline_map:
                    log_alert("New file detected", file_path, args.log, args.webhook)
            
            baseline_map = current_map

if __name__ == "__main__":
    main()