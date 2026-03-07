"""
SOFuzz - Seed Scheduler
"""

import random
from typing import Optional
from enum import Enum

from ..utils.logger import get_logger
from .queue import InputQueue


class ScheduleStrategy(Enum):
    """Scheduling strategies"""
    RANDOM = "random"
    ROUND_ROBIN = "round_robin"
    WEIGHTED = "weighted"
    FAVOR_SMALL = "favor_small"
    FAVOR_NEW = "favor_new"


class Scheduler:
    """
    Schedules seed selection for fuzzing
    
    Determines which seed to fuzz next based on
    various strategies.
    
    Usage:
        scheduler = Scheduler(strategy=ScheduleStrategy.WEIGHTED)
        seed = scheduler.select(queue)
    """
    
    def __init__(self, strategy: ScheduleStrategy = ScheduleStrategy.RANDOM):
        self.strategy = strategy
        self.logger = get_logger()
        
        # Round-robin state
        self.rr_index = 0
        
        # Statistics
        self.selections = 0
    
    def select(self, queue: InputQueue) -> Optional[bytes]:
        """
        Select next seed from queue
        
        Args:
            queue: Input queue
        
        Returns:
            Selected seed data or None
        """
        if queue.is_empty():
            return None
        
        self.selections += 1
        
        if self.strategy == ScheduleStrategy.RANDOM:
            return self._select_random(queue)
        elif self.strategy == ScheduleStrategy.ROUND_ROBIN:
            return self._select_round_robin(queue)
        elif self.strategy == ScheduleStrategy.WEIGHTED:
            return self._select_weighted(queue)
        elif self.strategy == ScheduleStrategy.FAVOR_SMALL:
            return self._select_favor_small(queue)
        elif self.strategy == ScheduleStrategy.FAVOR_NEW:
            return self._select_favor_new(queue)
        else:
            return self._select_random(queue)
    
    def _select_random(self, queue: InputQueue) -> bytes:
        """Random selection"""
        return queue.get()
    
    def _select_round_robin(self, queue: InputQueue) -> bytes:
        """Round-robin selection"""
        entries = queue.entries
        
        if not entries:
            return None
        
        self.rr_index = self.rr_index % len(entries)
        entry = entries[self.rr_index]
        self.rr_index += 1
        
        entry.times_selected += 1
        return entry.data
    
    def _select_weighted(self, queue: InputQueue) -> bytes:
        """Weighted selection based on priority"""
        return queue.get_weighted()
    
    def _select_favor_small(self, queue: InputQueue) -> bytes:
        """Favor smaller inputs"""
        entries = queue.entries
        
        if not entries:
            return None
        
        # Weight by inverse of size
        weights = [1.0 / (len(e.data) + 1) for e in entries]
        total = sum(weights)
        
        r = random.uniform(0, total)
        cumulative = 0
        
        for i, entry in enumerate(entries):
            cumulative += weights[i]
            if cumulative >= r:
                entry.times_selected += 1
                return entry.data
        
        return entries[-1].data
    
    def _select_favor_new(self, queue: InputQueue) -> bytes:
        """Favor newly added inputs"""
        entries = queue.entries
        
        if not entries:
            return None
        
        # Weight by inverse of times selected
        weights = [1.0 / (e.times_selected + 1) for e in entries]
        total = sum(weights)
        
        r = random.uniform(0, total)
        cumulative = 0
        
        for i, entry in enumerate(entries):
            cumulative += weights[i]
            if cumulative >= r:
                entry.times_selected += 1
                return entry.data
        
        return entries[-1].data
    
    def set_strategy(self, strategy: ScheduleStrategy) -> None:
        """Set scheduling strategy"""
        self.strategy = strategy
        self.rr_index = 0
    
    def get_stats(self) -> dict:
        """Get scheduler statistics"""
        return {
            'strategy': self.strategy.value,
            'selections': self.selections,
        }