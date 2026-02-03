import hashlib
import argparse
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def calculate_directory_map(target_folder):
    """Calculate the SHA256 hash of all files in a directory using parallel processing."""
    file_map = {}
    file_paths = []
    
    # Collect all file paths first
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            # Skip the log file to avoid infinite self-modification detection
            if file == "integrity_log.txt":
                continue
            file_paths.append(os.path.join(root, file))
    
    # Process files in parallel using thread pool
    with ThreadPoolExecutor() as executor:
        # Submit all hashing tasks
        future_to_path = {executor.submit(calculate_hash, path): path for path in file_paths}
        
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                file_map[path] = future.result()
            except Exception as e:
                print(f"Error hashing {path}: {e}")
    
    return file_map

def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] {message}")
    with open("integrity_log.txt", "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def main():
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument("-f", "--file", required=False, help="Path of file to monitor")
    parser.add_argument("-d", "--directory", required=False, help="Path of directory to monitor")

    args = parser.parse_args()

    if not args.file and not args.directory:
        print("Please provide a file or directory to monitor")
        sys.exit(1)

    # File monitoring mode
    if args.file:
        file_hash = calculate_hash(args.file)
        baseline_hash = file_hash
        print(f"File: {args.file}")
        print(f"Hash: {file_hash}")

        while True:
            time.sleep(5)
            current_hash = calculate_hash(args.file)
            if current_hash != baseline_hash:
                print("File has been modified!")
                print(f"Baseline Hash: {baseline_hash}")
                print(f"Current Hash: {current_hash}")
                baseline_hash = current_hash
                print(f"Baseline hash updated to {baseline_hash}")
                log_alert(f"File modified: {args.file} | Old: {baseline_hash[:16]}... | New: {current_hash[:16]}...")

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
            for file_path, baseline_hash in baseline_map.items():
                if file_path not in current_map:
                    print(f"File deleted: {file_path}")
                    log_alert(f"File deleted: {file_path}")
                elif current_map[file_path] != baseline_hash:
                    print(f"File modified: {file_path}")
                    print(f"  Old hash: {baseline_hash}")
                    print(f"  New hash: {current_map[file_path]}")
                    log_alert(f"File modified: {file_path} | Old: {baseline_hash[:16]}... | New: {current_map[file_path][:16]}...")
            
            # Check for new files
            for file_path in current_map:
                if file_path not in baseline_map:
                    print(f"New file detected: {file_path}")
                    log_alert(f"New file detected: {file_path}")
            
            baseline_map = current_map

if __name__ == "__main__":
    main()