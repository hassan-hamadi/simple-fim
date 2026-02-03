import hashlib
import argparse
import sys
import time
import os

def calculate_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {file_path}")
        sys.exit(1)

def calculate_directory_map(target_folder):
    """Calculate the SHA256 hash of all files in a directory."""
    file_map = {}
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            file_path = os.path.join(root, file)
            file_map[file_path] = calculate_hash(file_path)
    return file_map

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

    # Directory monitoring mode
    if args.directory:
        baseline_map = calculate_directory_map(args.directory)
        print(f"Monitoring directory: {args.directory}")
        print(f"Tracking {len(baseline_map)} files")

        while True:
            time.sleep(5)
            current_map = calculate_directory_map(args.directory)
            
            # Check for modified or deleted files
            for file_path, baseline_hash in baseline_map.items():
                if file_path not in current_map:
                    print(f"File deleted: {file_path}")
                elif current_map[file_path] != baseline_hash:
                    print(f"File modified: {file_path}")
                    print(f"  Old hash: {baseline_hash}")
                    print(f"  New hash: {current_map[file_path]}")
            
            # Check for new files
            for file_path in current_map:
                if file_path not in baseline_map:
                    print(f"New file detected: {file_path}")
            
            baseline_map = current_map

if __name__ == "__main__":
    main()