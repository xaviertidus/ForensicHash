ForensicHash: Python tool for digital evidence integrity. Decompresses archives, computes MD5/SHA1/SHA256/SHA512 hashes, verifies reports, signs outputs, logs custody. Supports TEXT/JSON/CSV, parallel processing. MIT License.

Copyright (c) 2025 xaviertidus

Repository: https://github.com/xaviertidus/ForensicHash
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import zipfile
import gzip
from pathlib import Path
import shutil
import tempfile
from tqdm import tqdm  # For progress bars; pip install tqdm
import multiprocessing  # For parallel processing
import json  # For JSON output
import csv  # For CSV output
import datetime  # For timestamps in custody log
import getpass  # For current user
import socket  # For hostname
try:
    import magic  # For file type validation; pip install python-magic
except ImportError:
    magic = None

VERSION = '2.0'  # Script version for custody logging

def get_hash_algorithm(algo_name):
    """Get hashlib algorithm by name."""
    algo_name = algo_name.lower()
    if algo_name == 'md5':
        return hashlib.md5
    elif algo_name == 'sha1':
        return hashlib.sha1
    elif algo_name == 'sha256':
        return hashlib.sha256
    elif algo_name == 'sha512':
        return hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash algorithm: {algo_name}")

def calculate_hashes(file_path, algorithms, show_progress=False):
    """Calculate multiple hashes for a given file, with optional progress bar."""
    hash_objects = {algo: get_hash_algorithm(algo)() for algo in algorithms}
    
    file_size = os.path.getsize(file_path)
    
    if show_progress:
        print(f"Hashing {Path(file_path).name} with {', '.join(algorithms)}...")
        with open(file_path, "rb") as f, tqdm(total=file_size, unit='B', unit_scale=True, desc="Hashing") as pbar:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
                pbar.update(len(chunk))
    else:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
    
    return {algo: hash_obj.hexdigest() for algo, hash_obj in hash_objects.items()}

def decompress_archive(archive_path, extract_dir, show_progress=False):
    """Decompress an archive and return a list of extracted file paths, with optional progress feedback."""
    archive_path = Path(archive_path)
    extract_dir = Path(extract_dir)
    extracted_files = []

    if not archive_path.exists():
        print(f"Error: Archive {archive_path} does not exist.")
        return extracted_files

    if show_progress:
        print(f"Decompressing {archive_path.name}...")

    try:
        if archive_path.suffix == ".gz":
            with gzip.open(archive_path, 'rb') as f_in:
                output_path = extract_dir / archive_path.stem
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                extracted_files.append(output_path)
        
        elif archive_path.suffix in [".tar", ".tgz", ".tbz2", ".tar.gz", ".tar.bz2"]:
            with tarfile.open(archive_path, 'r:*') as tar:
                tar.extractall(path=extract_dir)
                extracted_files = [extract_dir / member.name for member in tar.getmembers() if member.isfile()]
        
        elif archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                extracted_files = [extract_dir / name for name in zip_ref.namelist() if not name.endswith('/')]
        
        elif archive_path.suffix == ".7z":
            try:
                if show_progress:
                    process = subprocess.Popen(
                        ["7z", "x", str(archive_path), f"-o{extract_dir}", "-y"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            sys.stdout.write(output)
                            sys.stdout.flush()
                    process.communicate()
                else:
                    subprocess.run(
                        ["7z", "x", str(archive_path), f"-o{extract_dir}", "-y"],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                extracted_files = [f for f in extract_dir.rglob("*") if f.is_file()]
            except subprocess.CalledProcessError as e:
                print(f"Error extracting {archive_path}: {e.stderr}")
                return []
        
        else:
            print(f"Unsupported archive format for {archive_path}")
            return []
    
    except Exception as e:
        print(f"Error processing {archive_path}: {str(e)}")
        return []
    
    if show_progress:
        print(f"Decompression complete for {archive_path.name}.")
    
    return extracted_files

def validate_file_type(file_path, restrict_types):
    """Validate file type using extension or MIME type."""
    if not restrict_types:
        return True
    
    file_path = Path(file_path)
    for typ in restrict_types:
        if typ.startswith('.'):
            # Extension check
            if file_path.suffix.lower() == typ.lower():
                return True
        else:
            # MIME type check
            if magic is None:
                print("Warning: python-magic not installed, skipping MIME validation.")
                return True
            mime = magic.from_file(str(file_path), mime=True)
            if mime == typ:
                return True
    return False

def parse_report_for_verify(report_file):
    """Parse the text report to extract expected hashes."""
    expected = {}
    with open(report_file, 'r') as f:
        content = f.read().strip().split('\n\n')  # Split by double newline for each block
        for block in content:
            lines = block.split('\n')
            bundle = lines[0].split(': ', 1)[1]
            file_name = lines[1].split(': ', 1)[1]
            # Skip SIZE
            hashes = {}
            for line in lines[3:]:
                if ': ' in line:
                    algo, hsh = line.split(': ', 1)
                    hashes[algo] = hsh
            key = (bundle, file_name)
            expected[key] = hashes
    return expected

def generate_report(bundle_name, file_name, file_size, hashes, format='TEXT'):
    """Generate report in specified format."""
    if format == 'TEXT':
        report = f"BUNDLE: {bundle_name}\nFILE: {file_name}\nSIZE: {file_size:,} bytes\n"
        for algo, hsh in hashes.items():
            report += f"{algo.upper()}: {hsh}\n"
        return report
    elif format == 'JSON':
        data = {
            'bundle': bundle_name,
            'file': file_name,
            'size': file_size,
            'hashes': hashes
        }
        return json.dumps(data) + '\n'
    elif format == 'CSV':
        return {'bundle': bundle_name, 'file': file_name, 'size': file_size, **hashes}
    else:
        raise ValueError("Unsupported format")

def process_file(file_path, bundle_name, algorithms, output_file=None, format='TEXT', show_progress=False, verify_expected=None, error_log=None):
    """Process a single file: validate, calculate hashes, verify if needed, generate report."""
    file_path = Path(file_path)
    file_name = file_path.name
    try:
        if show_progress:
            print(f"Processing file {file_name}...")
        
        file_size = file_path.stat().st_size
        hashes = calculate_hashes(file_path, algorithms, show_progress)
        
        if verify_expected:
            key = (bundle_name, file_name)
            expected_hashes = verify_expected.get(key)
            if not expected_hashes:
                mismatch = f"No expected hashes for {key}"
                print(mismatch)
                if error_log:
                    with open(error_log, 'a') as el:
                        el.write(mismatch + '\n')
                return
            mismatches = []
            for algo in algorithms:
                if hashes[algo] != expected_hashes.get(algo.upper()):
                    mismatches.append(algo)
            if mismatches:
                mismatch = f"Mismatch for {key} in {', '.join(mismatches)}"
                print(mismatch)
                if error_log:
                    with open(error_log, 'a') as el:
                        el.write(mismatch + '\n')
            else:
                print(f"Match for {key}")
            return  # No report in verify mode
        
        report = generate_report(bundle_name, file_name, file_size, hashes, format)
        
        if format in ['TEXT', 'JSON']:
            print(report)
        
        if output_file:
            with open(output_file, 'a') as f:
                if format in ['TEXT', 'JSON']:
                    f.write(report + "\n")
                elif format == 'CSV':
                    pass  # Handle in caller
    except Exception as e:
        error_msg = f"Error processing file {file_name}: {str(e)}"
        print(error_msg)
        if error_log:
            with open(error_log, 'a') as el:
                el.write(error_msg + '\n')

def process_archive(args_tuple):
    """Wrapper for multiprocessing: process a single archive or file."""
    archive_path, output_file, skip_decompress, working_dir, delete_after, show_progress, algorithms, restrict_types, format, verify_expected, error_log, sign_key = args_tuple
    archive_path = Path(archive_path)
    archive_name = archive_path.name
    csv_rows = []
    
    try:
        if skip_decompress:
            if show_progress:
                print(f"Skipping decompression for {archive_name}.")
            if validate_file_type(archive_path, restrict_types):
                process_file(archive_path, archive_name, algorithms, output_file, format, show_progress, verify_expected, error_log)
            else:
                print(f"File {archive_name} does not match restricted types.")
            return []
        
        if working_dir is None:
            temp_dir = tempfile.TemporaryDirectory()
            extract_dir = Path(temp_dir.name)
        else:
            extract_dir = Path(working_dir) / archive_name.replace('.', '_')
            extract_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = decompress_archive(archive_path, extract_dir, show_progress)
        
        for file_path in extracted_files:
            if validate_file_type(file_path, restrict_types):
                if format == 'CSV':
                    file_size = file_path.stat().st_size
                    hashes = calculate_hashes(file_path, algorithms, show_progress)
                    row = generate_report(archive_name, file_path.name, file_size, hashes, format)
                    csv_rows.append(row)
                else:
                    process_file(file_path, archive_name, algorithms, output_file, format, show_progress, verify_expected, error_log)
            else:
                print(f"File {file_path.name} does not match restricted types.")
        
        if delete_after:
            if working_dir is None:
                temp_dir.cleanup()
            else:
                shutil.rmtree(extract_dir)
                if show_progress:
                    print(f"Deleted extracted files for {archive_name}.")
        else:
            if show_progress:
                print(f"Retained extracted files in {extract_dir}.")
        
        return csv_rows
    except Exception as e:
        error_msg = f"Error processing archive {archive_name}: {str(e)}"
        print(error_msg)
        if error_log:
            with open(error_log, 'a') as el:
                el.write(error_msg + '\n')
        return []

def sign_output(output_file, sign_key):
    """Sign the output file using GPG."""
    if not output_file:
        print("Warning: No output file to sign.")
        return
    sig_file = f"{output_file}.sig"
    try:
        subprocess.run(
            ['gpg', '--sign', '-u', sign_key, '--output', sig_file, '--detach-sign', output_file],
            check=True
        )
        print(f"Signed output: {sig_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error signing file: {e}")

def log_custody(log_file, files, args):
    """Log chain of custody information."""
    timestamp = datetime.datetime.now().isoformat()
    user = getpass.getuser()
    host = socket.gethostname()
    command = ' '.join(sys.argv)
    entry = f"""
Timestamp: {timestamp}
User: {user}
Host: {host}
Script Version: {VERSION}
Processed Files: {', '.join(files)}
Command: {command}
"""
    with open(log_file, 'a') as lf:
        lf.write(entry + "\n")

def main():
    """Main function to handle command-line arguments and process files."""
    parser = argparse.ArgumentParser(
        description="ForensicHash: Decompress archives (optional), generate/verify hash reports for digital evidence integrity checks."
    )
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("--skip-decompress", action="store_true", help="Skip decompression and hash input files directly")
    parser.add_argument("--retain-after", action="store_true", help="Retain extracted files after processing (overrides default delete)")
    parser.add_argument("--working-dir", help="Working directory for extraction (defaults to temporary dir)")
    parser.add_argument("--show-progress", action="store_true", help="Show progress bars and step details in terminal")
    parser.add_argument("--hashes", default="SHA1,MD5", help="Comma-separated algorithms (e.g., MD5,SHA1,SHA256,SHA512)")
    parser.add_argument("--sign", help="GPG key ID to sign the output report")
    parser.add_argument("--log-custody", help="File to log chain of custody information")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel processes (default 1)")
    parser.add_argument("--verify", help="Report file to verify against (enables verification mode)")
    parser.add_argument("--restrict-types", help="Comma-separated file types to restrict to (extensions like .raw or MIME like image/jpeg)")
    parser.add_argument("--format", default="TEXT", choices=['TEXT', 'JSON', 'CSV'], help="Output format (TEXT, JSON, CSV)")
    parser.add_argument("--error-log", help="File to log errors")
    parser.add_argument("files", nargs="+", help="List of archive or files to process")
    
    args = parser.parse_args()
    
    delete_after = not args.retain_after
    algorithms = [a.strip().upper() for a in args.hashes.split(',')]
    restrict_types = [t.strip() for t in args.restrict_types.split(',')] if args.restrict_types else None
    verify_expected = parse_report_for_verify(args.verify) if args.verify else None
    
    if args.output and Path(args.output).exists():
        Path(args.output).unlink()
    
    if args.log_custody:
        log_custody(args.log_custody, args.files, args)
    
    if args.error_log and Path(args.error_log).exists():
        Path(args.error_log).unlink()
    
    process_args = [
        (file, args.output, args.skip_decompress, args.working_dir, delete_after, args.show_progress,
         algorithms, restrict_types, args.format, verify_expected, args.error_log, args.sign)
        for file in args.files
    ]
    
    csv_all_rows = []
    if args.parallel > 1:
        with multiprocessing.Pool(processes=args.parallel) as pool:
            results = pool.map(process_archive, process_args)
            for rows in results:
                csv_all_rows.extend(rows)
    else:
        for pa in process_args:
            rows = process_archive(pa)
            csv_all_rows.extend(rows)
    
    if args.format == 'CSV' and not args.verify:
        headers = ['bundle', 'file', 'size'] + algorithms
        csv_data = [headers]
        for row in csv_all_rows:
            csv_data.append([row.get(h.lower(), '') for h in headers])
        
        for line in csv_data:
            print(','.join(map(str, line)))
        
        if args.output:
            with open(args.output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(csv_data)
    
    if args.sign and args.output and not args.verify:
        sign_output(args.output, args.sign)

if __name__ == "__main__":
    main()
