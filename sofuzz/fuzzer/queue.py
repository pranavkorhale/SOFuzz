"""
SOFuzz - Input Queue Management
"""

import random
import hashlib
from typing import List, Optional, Set
from dataclasses import dataclass, field
from collections import deque

from ..utils.logger import get_logger


@dataclass
class QueueEntry:
    """Entry in the input queue"""
    data: bytes
    hash: str
    times_selected: int = 0
    times_mutated: int = 0
    found_crashes: int = 0
    priority: float = 1.0
    
    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.md5(self.data).hexdigest()


class InputQueue:
    """
    Manages queue of inputs for fuzzing
    
    Features:
    - Deduplication
    - Priority-based selection
    - Size limits
    
    Usage:
        queue = InputQueue()
        queue.add(seed_data)
        
        input_data = queue.get()
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.logger = get_logger()
        
        # Queue storage
        self.entries: List[QueueEntry] = []
        self.hashes: Set[str] = set()
        
        # Statistics
        self.total_added = 0
        self.duplicates_skipped = 0
    
    def add(self, data: bytes, priority: float = 1.0) -> bool:
        """
        Add input to queue
        
        Args:
            data: Input data
            priority: Priority for selection
        
        Returns:
            True if added, False if duplicate
        """
        # Calculate hash
        data_hash = hashlib.md5(data).hexdigest()
        
        # Check for duplicate
        if data_hash in self.hashes:
            self.duplicates_skipped += 1
            return False
        
        # Check size limit
        if len(self.entries) >= self.max_size:
            self._evict()
        
        # Add entry
        entry = QueueEntry(
            data=data,
            hash=data_hash,
            priority=priority
        )
        
        self.entries.append(entry)
        self.hashes.add(data_hash)
        self.total_added += 1
        
        return True
    
    def get(self) -> Optional[bytes]:
        """
        Get next input from queue
        
        Returns:
            Input data or None if queue is empty
        """
        if not self.entries:
            return None
        
        # Simple random selection for now
        entry = random.choice(self.entries)
        entry.times_selected += 1
        
        return entry.data
    
    def get_weighted(self) -> Optional[bytes]:
        """
        Get input based on priority weights
        
        Returns:
            Input data or None if queue is empty
        """
        if not self.entries:
            return None
        
        # Calculate total priority
        total_priority = sum(e.priority for e in self.entries)
        
        if total_priority <= 0:
            return self.get()
        
        # Weighted selection
        r = random.uniform(0, total_priority)
        cumulative = 0
        
        for entry in self.entries:
            cumulative += entry.priority
            if cumulative >= r:
                entry.times_selected += 1
                return entry.data
        
        # Fallback
        return self.entries[-1].data
    
    def _evict(self) -> None:
        """Evict lowest priority entries"""
        if not self.entries:
            return
        
        # Sort by priority and remove lowest
        self.entries.sort(key=lambda e: e.priority, reverse=True)
        
        # Remove bottom 10%
        evict_count = max(1, len(self.entries) // 10)
        
        for _ in range(evict_count):
            if self.entries:
                entry = self.entries.pop()
                self.hashes.discard(entry.hash)
    
    def update_priority(self, data: bytes, delta: float) -> None:
        """Update priority of an entry"""
        data_hash = hashlib.md5(data).hexdigest()
        
        for entry in self.entries:
            if entry.hash == data_hash:
                entry.priority += delta
                entry.priority = max(0.1, entry.priority)  # Minimum priority
                break
    
    def mark_crash(self, data: bytes) -> None:
        """Mark that an input caused a crash"""
        data_hash = hashlib.md5(data).hexdigest()
        
        for entry in self.entries:
            if entry.hash == data_hash:
                entry.found_crashes += 1
                entry.priority += 5.0  # Boost priority
                break
    
    def size(self) -> int:
        """Get queue size"""
        return len(self.entries)
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return len(self.entries) == 0
    
    def clear(self) -> None:
        """Clear the queue"""
        self.entries.clear()
        self.hashes.clear()
    
    def get_all(self) -> List[bytes]:
        """Get all inputs"""
        return [e.data for e in self.entries]
    
    def contains(self, data: bytes) -> bool:
        """Check if input is in queue"""
        data_hash = hashlib.md5(data).hexdigest()
        return data_hash in self.hashes
    
    def get_stats(self) -> dict:
        """Get queue statistics"""
        return {
            'size': len(self.entries),
            'total_added': self.total_added,
            'duplicates_skipped': self.duplicates_skipped,
            'max_size': self.max_size,
        }