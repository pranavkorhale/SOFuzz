"""
SOFuzz - Mutator Tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sofuzz.mutator.mutator import Mutator
from sofuzz.mutator.strategies.bitflip import BitFlipStrategy
from sofuzz.mutator.strategies.byteflip import ByteFlipStrategy
from sofuzz.mutator.strategies.arithmetic import ArithmeticStrategy
from sofuzz.mutator.strategies.interesting import InterestingValueStrategy
from sofuzz.mutator.strategies.block import BlockStrategy
from sofuzz.mutator.strategies.dictionary import DictionaryStrategy


class TestMutator(unittest.TestCase):
    """Tests for main Mutator"""
    
    def setUp(self):
        self.mutator = Mutator()
    
    def test_mutate_empty_data(self):
        """Test mutating empty data"""
        result = self.mutator.mutate(b'')
        self.assertEqual(result, b'')
    
    def test_mutate_returns_bytes(self):
        """Test that mutate returns bytes"""
        data = b'Hello, World!'
        result = self.mutator.mutate(data)
        self.assertIsInstance(result, bytes)
    
    def test_mutate_changes_data(self):
        """Test that mutation changes data (statistically)"""
        data = b'A' * 100
        different_count = 0
        
        for _ in range(10):
            result = self.mutator.mutate(data)
            if result != data:
                different_count += 1
        
        # At least some mutations should change the data
        self.assertGreater(different_count, 0)
    
    def test_generate_variants(self):
        """Test generating multiple variants"""
        data = b'Test data'
        variants = self.mutator.generate_variants(data, count=5)
        
        self.assertEqual(len(variants), 5)
        for variant in variants:
            self.assertIsInstance(variant, bytes)


class TestBitFlipStrategy(unittest.TestCase):
    """Tests for BitFlipStrategy"""
    
    def setUp(self):
        self.strategy = BitFlipStrategy()
    
    def test_mutate_empty(self):
        """Test with empty data"""
        result = self.strategy.mutate(bytearray())
        self.assertEqual(len(result), 0)
    
    def test_mutate_single_byte(self):
        """Test with single byte"""
        data = bytearray([0x00])
        result = self.strategy.mutate(data)
        self.assertEqual(len(result), 1)


class TestByteFlipStrategy(unittest.TestCase):
    """Tests for ByteFlipStrategy"""
    
    def setUp(self):
        self.strategy = ByteFlipStrategy()
    
    def test_mutate_returns_bytearray(self):
        """Test that mutation returns bytearray"""
        data = bytearray(b'Test')
        result = self.strategy.mutate(data)
        self.assertIsInstance(result, bytearray)


class TestArithmeticStrategy(unittest.TestCase):
    """Tests for ArithmeticStrategy"""
    
    def setUp(self):
        self.strategy = ArithmeticStrategy()
    
    def test_mutate_preserves_length(self):
        """Test that mutation preserves data length"""
        data = bytearray(b'TestData')
        original_len = len(data)
        result = self.strategy.mutate(data)
        self.assertEqual(len(result), original_len)


class TestInterestingValueStrategy(unittest.TestCase):
    """Tests for InterestingValueStrategy"""
    
    def setUp(self):
        self.strategy = InterestingValueStrategy()
    
    def test_has_interesting_values(self):
        """Test that interesting values are defined"""
        self.assertGreater(len(self.strategy.interesting_8), 0)
        self.assertGreater(len(self.strategy.interesting_16), 0)
        self.assertGreater(len(self.strategy.interesting_32), 0)


class TestBlockStrategy(unittest.TestCase):
    """Tests for BlockStrategy"""
    
    def setUp(self):
        self.strategy = BlockStrategy()
    
    def test_mutate_can_change_length(self):
        """Test that block mutations can change length"""
        data = bytearray(b'A' * 50)
        results = []
        
        for _ in range(20):
            result = self.strategy.mutate(bytearray(data))
            results.append(len(result))
        
        # At least some should have different lengths
        unique_lengths = set(results)
        self.assertGreater(len(unique_lengths), 1)


class TestDictionaryStrategy(unittest.TestCase):
    """Tests for DictionaryStrategy"""
    
    def setUp(self):
        self.strategy = DictionaryStrategy()
    
    def test_has_default_tokens(self):
        """Test that default tokens are loaded"""
        self.assertGreater(len(self.strategy.tokens), 0)
    
    def test_add_token(self):
        """Test adding custom token"""
        initial_count = len(self.strategy.tokens)
        self.strategy.add_token(b'CUSTOM_TOKEN')
        self.assertEqual(len(self.strategy.tokens), initial_count + 1)
    
    def test_clear_tokens(self):
        """Test clearing all tokens"""
        self.strategy.clear()
        self.assertEqual(len(self.strategy.tokens), 0)
    
    def test_reset_tokens(self):
        """Test resetting to default tokens"""
        self.strategy.clear()
        self.strategy.reset()
        self.assertGreater(len(self.strategy.tokens), 0)


if __name__ == '__main__':
    unittest.main()