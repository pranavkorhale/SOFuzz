"""
SOFuzz - Analyzer Tests
"""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sofuzz.analyzer.elf_parser import ELFParser
from sofuzz.analyzer.symbol_extractor import SymbolExtractor
from sofuzz.analyzer.function_analyzer import FunctionAnalyzer


class TestELFParser(unittest.TestCase):
    """Tests for ELFParser"""
    
    def test_parse_invalid_file(self):
        """Test parsing non-existent file"""
        parser = ELFParser("/nonexistent/file.so")
        result = parser.parse()
        
        self.assertFalse(result.is_valid)
        self.assertIsNotNone(result.error)
    
    def test_parse_non_elf_file(self):
        """Test parsing non-ELF file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Not an ELF file")
            temp_path = f.name
        
        try:
            parser = ELFParser(temp_path)
            result = parser.parse()
            
            self.assertFalse(result.is_valid)
        finally:
            os.unlink(temp_path)
    
    def test_parse_minimal_elf(self):
        """Test parsing minimal ELF header"""
        # Create minimal ELF file
        elf_data = bytearray()
        elf_data.extend(b'\x7fELF')  # Magic
        elf_data.extend(b'\x02')     # 64-bit
        elf_data.extend(b'\x01')     # Little endian
        elf_data.extend(b'\x01')     # ELF version
        elf_data.extend(b'\x00' * 9) # Padding
        elf_data.extend(b'\x03\x00') # ET_DYN
        elf_data.extend(b'\x3e\x00') # x86_64
        elf_data.extend(b'\x00' * 44) # Rest of header
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(elf_data)
            temp_path = f.name
        
        try:
            parser = ELFParser(temp_path)
            result = parser.parse()
            
            self.assertTrue(result.is_valid)
            self.assertTrue(result.header.is_64bit)
            self.assertTrue(result.header.is_little_endian)
        finally:
            os.unlink(temp_path)


class TestSymbolExtractor(unittest.TestCase):
    """Tests for SymbolExtractor"""
    
    def test_extract_invalid_file(self):
        """Test extracting from non-existent file"""
        extractor = SymbolExtractor("/nonexistent/file.so")
        result = extractor.extract()
        
        self.assertEqual(result.total_count, 0)


class TestFunctionAnalyzer(unittest.TestCase):
    """Tests for FunctionAnalyzer"""
    
    def test_analyze_invalid_file(self):
        """Test analyzing non-existent file"""
        analyzer = FunctionAnalyzer("/nonexistent/file.so")
        result = analyzer.analyze()
        
        self.assertFalse(result.is_valid)
        self.assertTrue(len(result.errors) > 0)


if __name__ == '__main__':
    unittest.main()