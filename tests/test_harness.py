"""
SOFuzz - Harness Tests
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sofuzz.harness.generator import HarnessGenerator, GeneratedHarness
from sofuzz.harness.compiler import HarnessCompiler, CompileResult


class TestHarnessGenerator(unittest.TestCase):
    """Tests for HarnessGenerator"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Create a fake .so file for testing
        self.fake_so = os.path.join(self.temp_dir, "libtest.so")
        with open(self.fake_so, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 60)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_generate_harness(self):
        """Test generating a harness"""
        generator = HarnessGenerator(self.fake_so, output_dir=self.temp_dir)
        result = generator.generate_for_function("test_function")
        
        self.assertIsInstance(result, GeneratedHarness)
        self.assertEqual(result.function_name, "test_function")
        self.assertTrue(result.is_generated)
        self.assertTrue(os.path.exists(result.source_path))
    
    def test_generate_jni_harness(self):
        """Test generating JNI harness"""
        generator = HarnessGenerator(self.fake_so, output_dir=self.temp_dir)
        result = generator.generate_for_function("Java_com_test_func", is_jni=True)
        
        self.assertTrue(result.is_generated)
        
        # Check that JNI template was used
        content = open(result.source_path).read()
        self.assertIn("JNIEnv", content)
    
    def test_list_generated_harnesses(self):
        """Test listing generated harnesses"""
        generator = HarnessGenerator(self.fake_so, output_dir=self.temp_dir)
        generator.generate_for_function("func1")
        generator.generate_for_function("func2")
        
        harnesses = generator.list_generated_harnesses()
        self.assertEqual(len(harnesses), 2)
    
    def test_cleanup(self):
        """Test cleanup of generated harnesses"""
        generator = HarnessGenerator(self.fake_so, output_dir=self.temp_dir)
        generator.generate_for_function("test_function")
        
        self.assertTrue(os.path.exists(generator.harness_dir))
        
        generator.cleanup()
        
        self.assertFalse(os.path.exists(generator.harness_dir))


class TestHarnessCompiler(unittest.TestCase):
    """Tests for HarnessCompiler"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.compiler = HarnessCompiler()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_compile_nonexistent_file(self):
        """Test compiling non-existent file"""
        result = self.compiler.compile("/nonexistent/file.c")
        
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
    
    def test_compile_invalid_c_code(self):
        """Test compiling invalid C code"""
        source_path = os.path.join(self.temp_dir, "invalid.c")
        with open(source_path, 'w') as f:
            f.write("This is not valid C code!!!")
        
        result = self.compiler.compile(source_path)
        
        self.assertFalse(result.success)
    
    def test_compile_valid_c_code(self):
        """Test compiling valid C code"""
        source_path = os.path.join(self.temp_dir, "valid.c")
        with open(source_path, 'w') as f:
            f.write("""
#include <stdio.h>
int main() {
    printf("Hello\\n");
    return 0;
}
""")
        
        result = self.compiler.compile(source_path)
        
        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(result.binary_path))
    
    def test_get_compiler_version(self):
        """Test getting compiler version"""
        version = self.compiler.get_compiler_version()
        # May be None if gcc is not installed
        if version:
            self.assertIsInstance(version, str)


if __name__ == '__main__':
    unittest.main()