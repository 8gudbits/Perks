# Perks

Perks is a lightweight Windows command-line tool for generating and verifying file hashes (MD5, SHA1, SHA256, SHA512) across directories with checksum persistence.

## Usage

```bash
Perks.exe -[md5|sha1|sha256|sha512] <path> [-f/--file <outfile.perks>] [-n/--nobanner]
Perks.exe -v/--verify <path> [-f/--file <infile.perks>] [-n/--nobanner]
```

## Options

- `-[md5|sha1|sha256|sha512]` Specify the hash algorithm to use
- `-v, --verify` Verify files against a previously generated hash file
- `-f, --file <file>` Specify input/output file (default: <algorithm>.perks)
- `-n, --nobanner` Suppresses the banner output
- `-h, --help` Displays the help menu

## Examples

```bash
# Generate SHA256 hashes of current directory
Perks.exe -sha256

# Generate MD5 hashes with custom output file
Perks.exe -md5 C:\MyProject -f project_hashes.perks

# Verify files against hash file
Perks.exe -v C:\MyProject -f hashes.perks

# Suppress banner output
Perks.exe -n -sha256 C:\MyFolder
```

## Download exe for Windows

This tool is part of the [8gudbitsKit](https://github.com/8gudbits/8gudbitsKit) project. To download the executable for Windows, visit the [8gudbitsKit](https://github.com/8gudbits/8gudbitsKit) repository.

## For the Tech People

- Uses Windows CryptoAPI (`wincrypt.h`) for native hash computation
- Supports multiple algorithms: MD5, SHA1, SHA256, and SHA512
- Stores hash algorithm metadata in output files for automatic detection during verification
- Provides detailed verification reports with pass/fail status and summary statistics
- Implements a robust CLI argument parser with intelligent defaults
- Handles long file paths with extended buffer support

