import hashlib
import argparse
import sys
import time

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

def main():
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument("-f", "--file", required=True, help="Path of file to monitor")

    args = parser.parse_args()

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

if __name__ == "__main__":
    main()