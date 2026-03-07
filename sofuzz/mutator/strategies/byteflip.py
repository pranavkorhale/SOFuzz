"""
SOFuzz - Byte Flip Mutation Strategy
"""

import random
from typing import List


class ByteFlipStrategy:
    """
    Byte flip mutation strategy
    
    Modifies entire bytes in the input data.
    """
    
    def __init__(self):
        self.name = "byteflip"
    
    def mutate(self, data: bytearray) -> bytearray:
        """
        Flip/modify random bytes in data
        
        Args:
            data: Input data as bytearray
        
        Returns:
            Mutated data
        """
        if len(data) == 0:
            return data
        
        mutation_type = random.choice([
            self._flip_single_byte,
            self._flip_two_bytes,
            self._flip_four_bytes,
            self._set_random_byte,
            self._set_zero_byte,
            self._set_max_byte,
        ])
        
        return mutation_type(data)
    
    def _flip_single_byte(self, data: bytearray) -> bytearray:
        """Flip all bits in a single byte"""
        idx = random.randint(0, len(data) - 1)
        data[idx] ^= 0xFF
        return data
    
    def _flip_two_bytes(self, data: bytearray) -> bytearray:
        """Flip all bits in two adjacent bytes"""
        if len(data) < 2:
            return self._flip_single_byte(data)
        
        idx = random.randint(0, len(data) - 2)
        data[idx] ^= 0xFF
        data[idx + 1] ^= 0xFF
        return data
    
    def _flip_four_bytes(self, data: bytearray) -> bytearray:
        """Flip all bits in four adjacent bytes"""
        if len(data) < 4:
            return self._flip_single_byte(data)
        
        idx = random.randint(0, len(data) - 4)
        for i in range(4):
            data[idx + i] ^= 0xFF
        return data
    
    def _set_random_byte(self, data: bytearray) -> bytearray:
        """Set a byte to a random value"""
        idx = random.randint(0, len(data) - 1)
        data[idx] = random.randint(0, 255)
        return data
    
    def _set_zero_byte(self, data: bytearray) -> bytearray:
        """Set a byte to zero"""
        idx = random.randint(0, len(data) - 1)
        data[idx] = 0
        return data
    
    def _set_max_byte(self, data: bytearray) -> bytearray:
        """Set a byte to max value (255)"""
        idx = random.randint(0, len(data) - 1)
        data[idx] = 255
        return data
    
    def randomize_bytes(self, data: bytearray, count: int = 1) -> bytearray:
        """
        Randomize multiple bytes
        
        Args:
            data: Input data
            count: Number of bytes to randomize
        
        Returns:
            Mutated data
        """
        if len(data) == 0:
            return data
        
        for _ in range(count):
            idx = random.randint(0, len(data) - 1)
            data[idx] = random.randint(0, 255)
        
        return data