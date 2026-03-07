"""
SOFuzz - Interesting Value Mutation Strategy
"""

import random
import struct
from typing import List

from ...utils.constants import INTERESTING_8, INTERESTING_16, INTERESTING_32


class InterestingValueStrategy:
    """
    Interesting value mutation strategy
    
    Replaces values with "interesting" boundary values that
    often trigger bugs (e.g., 0, -1, MAX_INT, etc.)
    """
    
    def __init__(self):
        self.name = "interesting"
        
        # Interesting 8-bit values
        self.interesting_8 = INTERESTING_8
        
        # Interesting 16-bit values
        self.interesting_16 = INTERESTING_16
        
        # Interesting 32-bit values
        self.interesting_32 = INTERESTING_32
    
    def mutate(self, data: bytearray) -> bytearray:
        """Apply interesting value mutation"""
        if len(data) == 0:
            return data
        
        mutation_type = random.choice([
            self._interesting_8,
            self._interesting_16_le,
            self._interesting_16_be,
            self._interesting_32_le,
            self._interesting_32_be,
        ])
        
        return mutation_type(data)
    
    def _interesting_8(self, data: bytearray) -> bytearray:
        """Insert interesting 8-bit value"""
        idx = random.randint(0, len(data) - 1)
        value = random.choice(self.interesting_8)
        data[idx] = value & 0xFF
        return data
    
    def _interesting_16_le(self, data: bytearray) -> bytearray:
        """Insert interesting 16-bit value (little endian)"""
        if len(data) < 2:
            return self._interesting_8(data)
        
        idx = random.randint(0, len(data) - 2)
        value = random.choice(self.interesting_16)
        data[idx:idx + 2] = struct.pack('<H', value & 0xFFFF)
        return data
    
    def _interesting_16_be(self, data: bytearray) -> bytearray:
        """Insert interesting 16-bit value (big endian)"""
        if len(data) < 2:
            return self._interesting_8(data)
        
        idx = random.randint(0, len(data) - 2)
        value = random.choice(self.interesting_16)
        data[idx:idx + 2] = struct.pack('>H', value & 0xFFFF)
        return data
    
    def _interesting_32_le(self, data: bytearray) -> bytearray:
        """Insert interesting 32-bit value (little endian)"""
        if len(data) < 4:
            return self._interesting_16_le(data)
        
        idx = random.randint(0, len(data) - 4)
        value = random.choice(self.interesting_32)
        data[idx:idx + 4] = struct.pack('<I', value & 0xFFFFFFFF)
        return data
    
    def _interesting_32_be(self, data: bytearray) -> bytearray:
        """Insert interesting 32-bit value (big endian)"""
        if len(data) < 4:
            return self._interesting_16_be(data)
        
        idx = random.randint(0, len(data) - 4)
        value = random.choice(self.interesting_32)
        data[idx:idx + 4] = struct.pack('>I', value & 0xFFFFFFFF)
        return data
    
    def add_interesting_value(self, size: int, value: int) -> None:
        """Add a custom interesting value"""
        if size == 8:
            if value not in self.interesting_8:
                self.interesting_8.append(value)
        elif size == 16:
            if value not in self.interesting_16:
                self.interesting_16.append(value)
        elif size == 32:
            if value not in self.interesting_32:
                self.interesting_32.append(value)