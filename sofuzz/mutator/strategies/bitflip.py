"""
SOFuzz - Bit Flip Mutation Strategy
"""

import random
from typing import List


class BitFlipStrategy:
    """
    Bit flip mutation strategy
    
    Flips individual bits in the input data.
    This is useful for finding off-by-one errors and
    boundary conditions.
    """
    
    def __init__(self):
        self.name = "bitflip"
    
    def mutate(self, data: bytearray) -> bytearray:
        """
        Flip random bits in data
        
        Args:
            data: Input data as bytearray
        
        Returns:
            Mutated data
        """
        if len(data) == 0:
            return data
        
        # Choose mutation type
        mutation_type = random.choice([
            self._flip_single_bit,
            self._flip_two_bits,
            self._flip_four_bits,
            self._flip_byte_bits,
        ])
        
        return mutation_type(data)
    
    def _flip_single_bit(self, data: bytearray) -> bytearray:
        """Flip a single random bit"""
        idx = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[idx] ^= (1 << bit)
        return data
    
    def _flip_two_bits(self, data: bytearray) -> bytearray:
        """Flip two adjacent bits"""
        idx = random.randint(0, len(data) - 1)
        bit = random.randint(0, 6)
        data[idx] ^= (3 << bit)  # 3 = 0b11
        return data
    
    def _flip_four_bits(self, data: bytearray) -> bytearray:
        """Flip four adjacent bits"""
        idx = random.randint(0, len(data) - 1)
        bit = random.randint(0, 4)
        data[idx] ^= (0xF << bit)  # 0xF = 0b1111
        return data
    
    def _flip_byte_bits(self, data: bytearray) -> bytearray:
        """Flip all bits in a byte"""
        idx = random.randint(0, len(data) - 1)
        data[idx] ^= 0xFF
        return data
    
    def flip_walking_bit(self, data: bytearray) -> List[bytearray]:
        """
        Generate all single-bit flip variants
        Useful for systematic testing
        
        Args:
            data: Input data
        
        Returns:
            List of all single-bit flip variants
        """
        variants = []
        
        for byte_idx in range(len(data)):
            for bit_idx in range(8):
                variant = bytearray(data)
                variant[byte_idx] ^= (1 << bit_idx)
                variants.append(variant)
        
        return variants