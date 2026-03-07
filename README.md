# SOFuzz 🔍

**Smart Fuzzer for Android Native Libraries (.so files)**

## 🎯 What is SOFuzz?

SOFuzz is an automated fuzzing tool that finds vulnerabilities in Android native libraries (.so files). It extracts native libraries from APK files, analyzes them, and automatically fuzzes their exported functions to find crashes and security bugs.

## ✨ Features

- **APK Extraction**: Automatically extract .so files from Android APKs
- **ELF Analysis**: Parse and analyze ELF binary structure
- **Auto Harness Generation**: Generate fuzzing harnesses automatically
- **Smart Mutations**: Structure-aware mutation strategies
- **Crash Detection**: Detect and classify crashes
- **Deduplication**: Remove duplicate crash reports
- **Detailed Reports**: Generate HTML/JSON reports

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/korhalepranav/sofuzz.git
cd sofuzz

# Install dependencies
pip install -r requirements.txt

# Install SOFuzz
pip install -e .
=======================================================
DAILY USE:

# 1. Navigate to project
cd /Users/pkorhale/Documents/project-work/SOFuzz

# 2. Activate virtual environment
source venv/bin/activate

# 3. Use sofuzz
sofuzz --help
sofuzz --target /path/to/library.so --analyze-only