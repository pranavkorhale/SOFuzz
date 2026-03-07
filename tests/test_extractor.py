"""
SOFuzz - Extractor Tests
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sofuzz.extractor.apk_extractor import APKExtractor
from sofuzz.extractor.arch_detector import ArchDetector


class TestArchDetector(unittest.TestCase):
    """Tests for ArchDetector"""
    
    def setUp(self):
        self.detector = ArchDetector()
    
    def test_get_system_arch(self):
        """Test getting system architecture"""
        arch = self.detector.get_system_arch()
        self.assertIsNotNone(arch)
        self.assertIsInstance(arch, str)
    
    def test_detect_invalid_file(self):
        """Test detection on non-existent file"""
        result = self.detector.detect("/nonexistent/file.so")
        self.assertFalse(result.is_valid)
        self.assertIsNotNone(result.error)
    
    def test_detect_non_elf_file(self):
        """Test detection on non-ELF file"""
        # Create temp file with random content
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"This is not an ELF file")
            temp_path = f.name
        
        try:
            result = self.detector.detect(temp_path)
            self.assertFalse(result.is_valid)
        finally:
            os.unlink(temp_path)


class TestAPKExtractor(unittest.TestCase):
    """Tests for APKExtractor"""
    
    def test_invalid_apk_path(self):
        """Test with non-existent APK"""
        with self.assertRaises(FileNotFoundError):
            APKExtractor("/nonexistent/app.apk")
    
    def test_invalid_apk_format(self):
        """Test with invalid APK (not a ZIP)"""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"Not a valid APK file")
            temp_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                APKExtractor(temp_path)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()