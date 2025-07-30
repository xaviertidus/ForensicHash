# ForensicHash

ForensicHash: Python tool for digital evidence integrity. Decompresses archives, computes MD5/SHA1/SHA256/SHA512 hashes, verifies reports, signs outputs, logs custody. Supports TEXT/JSON/CSV, parallel processing. MIT License.

## About
ForensicHash is a Python tool designed for digital evidence integrity checks in forensic analysis. It supports decompressing various archive formats (optional), computing multiple cryptographic hashes, verifying against previous reports, signing outputs with GPG, logging chain of custody, and generating reports in TEXT, JSON, or CSV formats. It also supports parallel processing for efficiency.

Repository: [https://github.com/xaviertidus/ForensicHash](https://github.com/xaviertidus/ForensicHash)

## Features
- Supports multiple archive formats: `.zip`, `.gz`, `.tar`, `.tar.gz`, `.tar.bz2`, `.7z`.
- Calculates configurable hashes (MD5, SHA1, SHA256, SHA512) for large files efficiently.
- Optional skipping of decompression for direct file hashing.
- Customizable working directory for extraction.
- Option to retain or delete extracted files post-processing.
- Progress feedback with steps and bars for long operations.
- Support for additional hash algorithms.
- Digital signature generation for reports using GPG.
- Chain of custody logging for forensic audit trails.
- Parallel processing of multiple files/archives.
- Verification mode to compare computed hashes against a previous report.
- File type restriction using extensions or MIME types.
- Output reports in TEXT, JSON, or CSV formats.
- Error logging for robust processing.

## Installation
1. Ensure Python 3.6+ is installed.
2. Install required dependencies:
   - For `.7z` support: Install `7-Zip` (Windows) or `p7zip` (Linux/Mac) and ensure `7z` is in your PATH.
   - For progress bars: `pip install tqdm`
   - For file type validation (MIME): `pip install python-magic` (requires system libmagic).
   - For signing: Ensure `gpg` is installed and configured with keys (see "Creating a GPG Key for Testing" below).
3. Clone the repository:
   ```
   git clone https://github.com/xaviertidus/ForensicHash.git
   ```

### Installing as a Package
To install ForensicHash as a CLI tool:
1. Clone the repository if not already done.
2. In the project root, run:
   ```
   pip install .
   ```
3. Now run `forensichash [options] file1 [file2 ...]` from anywhere.

For development (editable install):
```
pip install -e .
```

Alternatively, place `forensic_hash.py` in your project directory and run directly with `python forensic_hash.py [options] file1 [file2 ...]`.

No other external libraries are needed beyond Python's standard library and the above.

## Creating a GPG Key for Testing
To use the `--sign` option for signing reports, you need a GPG key. Follow these steps to create a test GPG key:

1. **Install GPG**:
   - Windows: Install Gpg4win (https://gpg4win.org).
   - Linux: Install `gnupg` (e.g., `sudo apt install gnupg` on Ubuntu).
   - Mac: Install via Homebrew (`brew install gnupg`).

2. **Generate a Test Key**:
   Run:
   ```
   gpg --gen-key
   ```
   - Select `(1) RSA and RSA (default)`.
   - Choose a key size (e.g., 2048 bits).
   - Set key validity (e.g., `0` for no expiration).
   - Enter a name (e.g., "Test User"), email (e.g., "test@example.com"), and optional passphrase.
   - Follow prompts to complete key generation.

3. **Get Your Key ID**:
   List your keys:
   ```
   gpg --list-keys
   ```
   Find the key ID (e.g., `A1B2C3D4`) in the `pub` line (after `rsa2048/`).

4. **Use with ForensicHash**:
   Use the key ID with the `--sign` option:
   ```
   forensichash --sign A1B2C3D4 -o report.txt disk.7z
   ```
   This creates `report.txt.sig` for verification.

**Note**: This is a basic key for testing. For production, use a secure passphrase and store keys safely.

## Usage
Run the script from the command line after installation:

```
forensichash [options] file1 [file2 ...]
```

Or, if not installed as a package:
```
python forensic_hash.py [options] file1 [file2 ...]
```

### Examples
- Basic with additional hashes:
  ```
  forensichash --hashes SHA256,MD5 -o report.txt disk.7z
  ```

- Sign the report:
  ```
  forensichash --sign YOUR_KEY_ID -o report.txt disk.7z
  ```

- Log custody and process in parallel:
  ```
  forensichash --log-custody custody.log --parallel 4 disk.7z memory.7z
  ```

- Verify against previous report:
  ```
  forensichash --verify old_report.txt disk.7z
  ```

- Restrict types and JSON output:
  ```
  forensichash --restrict-types .raw,image/jpeg --format JSON -o report.json disk.7z
  ```

- Error logging:
  ```
  forensichash --error-log errors.log disk.7z
  ```

### Options
- `-o, --output FILE`: Output file for the report (appended if multiple files).
- `--skip-decompress`: Treat inputs as plain files; skip decompression and hash directly.
- `--retain-after`: Keep extracted files after processing (overrides default deletion).
- `--working-dir DIR`: Directory for extraction (defaults to temporary dir).
- `--show-progress`: Display progress bars and step details in the terminal.
- `--hashes ALGOS`: Comma-separated algorithms (MD5, SHA1, SHA256, SHA512; default SHA1,MD5).
- `--sign KEY_ID`: GPG key ID to sign the output report (produces .sig file).
- `--log-custody FILE`: Log chain of custody metadata to this file.
- `--parallel N`: Number of parallel processes (default 1).
- `--verify FILE`: Verify mode: compare hashes against this report file.
- `--restrict-types TYPES`: Comma-separated extensions (.raw) or MIME types (image/jpeg) to process.
- `--format FMT`: Output format (TEXT, JSON, CSV; default TEXT).
- `--error-log FILE`: Log processing errors to this file.

## Report Formats
- **TEXT**: Human-readable blocks per file.
  ```
  BUNDLE: disk.7z
  FILE: disk.raw
  SIZE: 64,424,509,440 bytes
  SHA1: 945a8f34607ab9c1c7bb83b7e15f49445e10176b
  MD5: 2b915dce79a187582dc895445145b7a4
  ```
- **JSON**: Line-separated JSON objects per file.
- **CSV**: Single table with columns for bundle, file, size, and each hash algorithm.

## License
This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 xaviertidus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing
Contributions are welcome! Please submit issues or pull requests via [https://github.com/xaviertidus/ForensicHash](https://github.com/xaviertidus/ForensicHash).

## Contact
For questions or support, open an issue on the GitHub repository: [https://github.com/xaviertidus/ForensicHash](https://github.com/xaviertidus/ForensicHash).