"""
SOFuzz - Fuzzer Tests
"""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sofuzz.fuzzer.queue import InputQueue
from sofuzz.fuzzer.scheduler import Scheduler, ScheduleStrategy
from sofuzz.fuzzer.coverage import CoverageTracker


class TestInputQueue(unittest.TestCase):
    """Tests for InputQueue"""
    
    def setUp(self):
        self.queue = InputQueue()
    
    def test_add_input(self):
        """Test adding input to queue"""
        result = self.queue.add(b'Test input')
        self.assertTrue(result)
        self.assertEqual(self.queue.size(), 1)
    
    def test_add_duplicate(self):
        """Test adding duplicate input"""
        self.queue.add(b'Test input')
        result = self.queue.add(b'Test input')
        self.assertFalse(result)
        self.assertEqual(self.queue.size(), 1)
    
    def test_get_from_empty_queue(self):
        """Test getting from empty queue"""
        result = self.queue.get()
        self.assertIsNone(result)
    
    def test_get_returns_input(self):
        """Test getting input from queue"""
        self.queue.add(b'Test input')
        result = self.queue.get()
        self.assertEqual(result, b'Test input')
    
    def test_is_empty(self):
        """Test is_empty method"""
        self.assertTrue(self.queue.is_empty())
        self.queue.add(b'Test')
        self.assertFalse(self.queue.is_empty())
    
    def test_clear(self):
        """Test clearing queue"""
        self.queue.add(b'Test 1')
        self.queue.add(b'Test 2')
        self.queue.clear()
        self.assertTrue(self.queue.is_empty())
    
    def test_contains(self):
        """Test contains method"""
        self.queue.add(b'Test input')
        self.assertTrue(self.queue.contains(b'Test input'))
        self.assertFalse(self.queue.contains(b'Other input'))


class TestScheduler(unittest.TestCase):
    """Tests for Scheduler"""
    
    def setUp(self):
        self.scheduler = Scheduler()
        self.queue = InputQueue()
    
    def test_select_from_empty_queue(self):
        """Test selecting from empty queue"""
        result = self.scheduler.select(self.queue)
        self.assertIsNone(result)
    
    def test_select_returns_input(self):
        """Test selecting returns input"""
        self.queue.add(b'Test input')
        result = self.scheduler.select(self.queue)
        self.assertEqual(result, b'Test input')
    
    def test_set_strategy(self):
        """Test setting scheduler strategy"""
        self.scheduler.set_strategy(ScheduleStrategy.WEIGHTED)
        self.assertEqual(self.scheduler.strategy, ScheduleStrategy.WEIGHTED)


class TestCoverageTracker(unittest.TestCase):
    """Tests for CoverageTracker"""
    
    def setUp(self):
        self.tracker = CoverageTracker()
    
    def test_record_coverage(self):
        """Test recording coverage"""
        result = self.tracker.record(b'stdout', b'stderr', 0)
        self.assertIsNotNone(result.path_hash)
    
    def test_new_coverage_detection(self):
        """Test detecting new coverage"""
        result1 = self.tracker.record(b'output1', b'', 0)
        result2 = self.tracker.record(b'output2', b'', 0)
        result3 = self.tracker.record(b'output1', b'', 0)
        
        self.assertTrue(result1.new_coverage)
        self.assertTrue(result2.new_coverage)
        self.assertFalse(result3.new_coverage)
    
    def test_reset(self):
        """Test resetting coverage"""
        self.tracker.record(b'output', b'', 0)
        self.tracker.reset()
        
        self.assertEqual(self.tracker.unique_paths, 0)
        self.assertEqual(self.tracker.total_executions, 0)
    
    def test_get_stats(self):
        """Test getting coverage stats"""
        self.tracker.record(b'output1', b'', 0)
        self.tracker.record(b'output2', b'', 0)
        
        stats = self.tracker.get_stats()
        
        self.assertEqual(stats['total_executions'], 2)
        self.assertEqual(stats['unique_paths'], 2)


if __name__ == '__main__':
    unittest.main()