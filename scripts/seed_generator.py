#!/usr/bin/env python3
"""
SOFuzz - Intelligent Seed Generator
Extracts printable strings from the .rodata (read-only data) section of an ELF binary.
These strings become the "dictionary" or "seed corpus" for the fuzzer, drastically
improving initial code coverage compared to purely random bytes.
"""
import os
import sys
import string
import struct

def extract_strings_from_binary(filepath, min_length=4):
    """Yields all ASCII printable strings from a binary file."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    current_string = ""
    printable = set(string.printable.encode('ascii'))
    
    for byte in data:
        if byte in printable:
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                yield current_string
            current_string = ""
            
    if len(current_string) >= min_length:
        yield current_string

def generate_seed_corpus(so_path, output_dir):
    print(f"[*] Analyzing binary DNA for valid seeds: {so_path}")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    strings = set(extract_strings_from_binary(so_path))
    
    # Filter out obvious Assembly/Compiler noise
    valid_seeds = []
    for s in strings:
        if "GCC" in s or "clang" in s or "GLIBC" in s: continue
        if len(s) > 128: continue # Ignore massive blocks
        valid_seeds.append(s)
        
    print(f"[+] Extracted {len(valid_seeds)} unique high-value string seeds.")
    
    # Generate AFL++ Compatible Dictionary
    dict_path = os.path.join(output_dir, "sofuzz.dict")
    with open(dict_path, 'w') as f:
        for i, s in enumerate(valid_seeds):
            # Escape quotes and backslashes for AFL format
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            f.write(f'seed_{i}="{escaped}"\n')
            
    # Generate raw binary seed files for standard fuzzing
    raw_dir = os.path.join(output_dir, "raw_seeds")
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir)
        
    for i, s in enumerate(valid_seeds):
        with open(os.path.join(raw_dir, f"seed_{i}.bin"), 'wb') as f:
            f.write(s.encode('utf-8'))
            
    print(f"[+] Wrote AFL Dictionary to: {dict_path}")
    print(f"[+] Wrote {len(valid_seeds)} raw binary seeds to: {raw_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 seed_generator.py <path_to_so_file>")
        sys.exit(1)
        
    so_file = sys.argv[1]
    out_dir = os.path.join("output", "seeds_generated")
    generate_seed_corpus(so_file, out_dir)
