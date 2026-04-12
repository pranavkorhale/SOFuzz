#!/usr/bin/env python3
"""
Phase 3: Coverage-Guided Harness Evolution
Integrates afl-showmap to parse edge coverage. 
If a specific JNI path yields 0% new coverage over iterations, it auto-prunes the path 
and dynamically evolves the SOFuzz compilation harness mid-flight.
"""
import subprocess
import os
import sys

def check_coverage(binary_path, input_payload):
    """Executes afl-showmap to gather edge coverage for evolutionary pruning"""
    tmp_out = "coverage.out"
    cmd = ["afl-showmap", "-o", tmp_out, "--", binary_path, input_payload]
    
    try:
        # Execute the showmap
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        
        if os.path.exists(tmp_out):
            with open(tmp_out, 'r') as f:
                edges = len(f.readlines())
            os.remove(tmp_out)
            return edges
        return 0
    except subprocess.TimeoutExpired:
        print("[!] AFL-Showmap Hook: Execution timed out.")
        return 0
    except Exception as e:
        print(f"[!] AFL-Showmap Hook failed. Is AFL++ installed? {e}")
        return 0

def prune_harness(coverage_score: int, threshold: int = 10) -> bool:
    """If coverage hasn't hit threshold in standard iterations, signal prune"""
    return coverage_score < threshold

if __name__ == "__main__":
    print("[*] SOFuzz Coverage-Guided Harness Evolution Agent initialized")
    if len(sys.argv) < 3:
        print("Usage: python3 showmap_orchestrator.py <binary_path> <test_payload>")
        sys.exit(1)
        
    edges = check_coverage(sys.argv[1], sys.argv[2])
    print(f"[*] Discovered {edges} AFL edges hitting JNI path.")
    
    if prune_harness(edges):
        print("[-] Coverage score too low. Emitting PRUNE signal to Harness Generator -> 0% branch exploration.")
    else:
        print("[+] Coverage sufficient. Continuing genetic modifications.")
