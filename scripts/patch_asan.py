"""
Run this script to patch vuln_discovery.py to use AddressSanitizer.
Save as: scripts/patch_asan.py
Run:     python scripts/patch_asan.py
"""
import re

path = "scripts/vuln_discovery.py"
src  = open(path).read()

# patch library compile
src = src.replace(
    '["clang", "-shared", "-fPIC", "-g", "-o", LIB_PATH, VULN_C]',
    '["clang", "-shared", "-fPIC", "-g", "-fsanitize=address", "-o", LIB_PATH, VULN_C]'
)

# patch harness compile
src = src.replace(
    '["clang", "-o", bin_path, c_path, "-ldl"]',
    '["clang", "-fsanitize=address", "-o", bin_path, c_path, "-ldl"]'
)

open(path, "w").write(src)
print("[+] Patched vuln_discovery.py to use AddressSanitizer")
print("[*] Now run: python scripts/vuln_discovery.py")
