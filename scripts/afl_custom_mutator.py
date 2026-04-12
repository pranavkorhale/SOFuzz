#!/usr/bin/env python3
"""
SOFuzz - AFL++ Smart Custom Mutator 
Implementation of "Structure-Aware Fuzzing" for Android Native Libraries.
This script hooks directly into AFL++'s `AFL_PYTHON_MODULE` mutation queue.
It forces AFL to respect the JNI C structures by strictly boxing mutations 
into specific byte offsets (preventing structural serialization crashes).

Usage:
  export AFL_PYTHON_MODULE=afl_custom_mutator
  afl-fuzz -i seeds/ -o out/ -- ./harness
"""
import random

def init(seed):
    """Called once when AFL++ starts up."""
    random.seed(seed)
    # The structure context holds known bounds derived from SOFuzz's Constraint Engine
    return {"mutated_count": 0}

def fuzz(state, buf, add_buf, max_size):
    """
    The Custom Fuzz Mutation Routine.
    buf is the bytearray passed by AFL++.
    
    Strategy: 
    - Bytes 0-255: Core array structure (Pristine, non-corruptible)
    - Bytes 256-300: Actionable File Path (Mutatable)
    - Bytes 301-304: Length constraints (Pristine, non-corruptible)
    """
    mutated = bytearray(buf)
    
    # If the buffer is smaller than the mandated structure size, don't break it further
    if len(mutated) < 304:
        return bytes(buf)

    state["mutated_count"] += 1
    
    # Select randomly how many bytes in the constrained path segment we hit
    num_mutations = random.randint(1, 4)
    
    for _ in range(num_mutations):
        # Explicitly lock mutations to the Path Variable bounds (256 -> 300)
        target_idx = random.randint(256, 300)
        
        # Apply standard single-byte bitflip or replacement logic
        if random.choice([True, False]):
            mutated[target_idx] ^= random.randint(1, 255) # Bitflip
        else:
            mutated[target_idx] = random.randint(32, 126) # ASCII char constraint

    return bytes(mutated)

# Optional diagnostic trigger logic
if __name__ == "__main__":
    print("[*] AFL++ Python API Custom Mutator Loaded Successfully.")
    print("    Structural Bounds Set: [256-300] Mutable Zone Enabled.")
