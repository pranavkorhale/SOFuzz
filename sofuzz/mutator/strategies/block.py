"""
SOFuzz - Block Mutation Strategy
"""

import random
from typing import List


class BlockStrategy:
    """
    Block-based mutation strategy
    
    Performs operations on blocks of data:
    - Delete blocks
    - Insert blocks
    - Duplicate blocks
    - Swap blocks
    - Overwrite blocks
    """
    
    def __init__(self, max_block_size: int = 128):
        self.name = "block"
        self.max_block_size = max_block_size
    
    def mutate(self, data: bytearray) -> bytearray:
        """Apply block mutation"""
        if len(data) == 0:
            return data
        
        mutation_type = random.choice([
            self._delete_block,
            self._insert_block,
            self._duplicate_block,
            self._overwrite_block,
            self._swap_blocks,
            self._insert_repeated_byte,
        ])
        
        return mutation_type(data)
    
    def _delete_block(self, data: bytearray) -> bytearray:
        """Delete a random block of data"""
        if len(data) <= 1:
            return data
        
        block_size = random.randint(1, min(len(data) - 1, self.max_block_size))
        start_idx = random.randint(0, len(data) - block_size)
        
        del data[start_idx:start_idx + block_size]
        return data
    
    def _insert_block(self, data: bytearray) -> bytearray:
        """Insert a random block of data"""
        block_size = random.randint(1, self.max_block_size)
        insert_idx = random.randint(0, len(data))
        
        # Generate random bytes
        new_block = bytearray(random.randint(0, 255) for _ in range(block_size))
        
        data[insert_idx:insert_idx] = new_block
        return data
    
    def _duplicate_block(self, data: bytearray) -> bytearray:
        """Duplicate a block of data"""
        if len(data) < 2:
            return data
        
        block_size = random.randint(1, min(len(data), self.max_block_size))
        src_idx = random.randint(0, len(data) - block_size)
        
        block = data[src_idx:src_idx + block_size]
        
        insert_idx = random.randint(0, len(data))
        data[insert_idx:insert_idx] = block
        
        return data
    
    def _overwrite_block(self, data: bytearray) -> bytearray:
        """Overwrite a block with random data"""
        if len(data) == 0:
            return data
        
        block_size = random.randint(1, min(len(data), self.max_block_size))
        start_idx = random.randint(0, len(data) - block_size)
        
        for i in range(block_size):
            data[start_idx + i] = random.randint(0, 255)
        
        return data
    
    def _swap_blocks(self, data: bytearray) -> bytearray:
        """Swap two blocks of data"""
        if len(data) < 4:
            return data
        
        block_size = random.randint(1, min(len(data) // 2, self.max_block_size))
        
        # Ensure non-overlapping blocks
        idx1 = random.randint(0, len(data) // 2 - block_size)
        idx2 = random.randint(len(data) // 2, len(data) - block_size)
        
        # Swap
        block1 = data[idx1:idx1 + block_size]
        block2 = data[idx2:idx2 + block_size]
        
        data[idx1:idx1 + block_size] = block2
        data[idx2:idx2 + block_size] = block1
        
        return data
    
    def _insert_repeated_byte(self, data: bytearray) -> bytearray:
        """Insert a block of repeated bytes"""
        block_size = random.randint(1, self.max_block_size)
        insert_idx = random.randint(0, len(data))
        
        # Choose a byte to repeat
        byte_value = random.choice([0x00, 0xFF, 0x41, 0x0A, 0x20])
        
        new_block = bytearray([byte_value] * block_size)
        data[insert_idx:insert_idx] = new_block
        
        return data
    
    def clone_block(self, data: bytearray, times: int = 2) -> bytearray:
        """Clone a block multiple times"""
        if len(data) < 2:
            return data
        
        block_size = random.randint(1, min(len(data), self.max_block_size // times))
        src_idx = random.randint(0, len(data) - block_size)
        
        block = data[src_idx:src_idx + block_size]
        
        for _ in range(times):
            insert_idx = random.randint(0, len(data))
            data[insert_idx:insert_idx] = block
        
        return data