"""
SOFuzz - Arithmetic Mutation Strategy
"""

import random
import struct
from typing import List


class ArithmeticStrategy:
    """
    Arithmetic mutation strategy
    
    Performs arithmetic operations (add/subtract) on values
    in the input data. Useful for finding integer overflow bugs.
    """
    
    def __init__(self, arith_max: int = 35):
        self.name = "arithmetic"
        self.arith_max = arith_max
    
    def mutate(self, data: bytearray) -> bytearray:
        """Apply arithmetic mutation"""
        if len(data) == 0:
            return data
        
        mutation_type = random.choice([
            self._arith_8,
            self._arith_16_le,
            self._arith_16_be,
            self._arith_32_le,
            self._arith_32_be,
        ])
        
        return mutation_type(data)
    
    def _arith_8(self, data: bytearray) -> bytearray:
        """Add/subtract from a single byte"""
        idx = random.randint(0, len(data) - 1)
        delta = random.randint(1, self.arith_max)
        
        if random.random() < 0.5:
            data[idx] = (data[idx] + delta) & 0xFF
        else:
            data[idx] = (data[idx] - delta) & 0xFF
        
        return data
    
    def _arith_16_le(self, data: bytearray) -> bytearray:
        """Add/subtract from 16-bit value (little endian)"""
        if len(data) < 2:
            return self._arith_8(data)
        
        idx = random.randint(0, len(data) - 2)
        value = struct.unpack('<H', data[idx:idx + 2])[0]
        delta = random.randint(1, self.arith_max)
        
        if random.random() < 0.5:
            value = (value + delta) & 0xFFFF
        else:
            value = (value - delta) & 0xFFFF
        
        data[idx:idx + 2] = struct.pack('<H', value)
        return data
    
    def _arith_16_be(self, data: bytearray) -> bytearray:
        """Add/subtract from 16-bit value (big endian)"""
        if len(data) < 2:
            return self._arith_8(data)
        
        idx = random.randint(0, len(data) - 2)
        value = struct.unpack('>H', data[idx:idx + 2])[0]
        delta = random.randint(1, self.arith_max)
        
        if random.random() < 0.5:
            value = (value + delta) & 0xFFFF
        else:
            value = (value - delta) & 0xFFFF
        
        data[idx:idx + 2] = struct.pack('>H', value)
        return data
    
    def _arith_32_le(self, data: bytearray) -> bytearray:
        """Add/subtract from 32-bit value (little endian)"""
        if len(data) < 4:
            return self._arith_16_le(data)
        
        idx = random.randint(0, len(data) - 4)
        value = struct.unpack('<I', data[idx:idx + 4])[0]
        delta = random.randint(1, self.arith_max)
        
        if random.random() < 0.5:
            value = (value + delta) & 0xFFFFFFFF
        else:
            value = (value - delta) & 0xFFFFFFFF
        
        data[idx:idx + 4] = struct.pack('<I', value)
        return data
    
    def _arith_32_be(self, data: bytearray) -> bytearray:
        """Add/subtract from 32-bit value (big endian)"""
        if len(data) < 4:
            return self._arith_16_be(data)
        
        idx = random.randint(0, len(data) - 4)
        value = struct.unpack('>I', data[idx:idx + 4])[0]
        delta = random.randint(1, self.arith_max)
        
        if random.random() < 0.5:
            value = (value + delta) & 0xFFFFFFFF
        else:
            value = (value - delta) & 0xFFFFFFFF
        
        data[idx:idx + 4] = struct.pack('>I', value)
        return data
