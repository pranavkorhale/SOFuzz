"""
SOFuzz - Dictionary-Based Mutation Strategy
"""

import os
import random
from typing import List, Optional

from ...utils.logger import get_logger
from ...utils.file_utils import FileUtils


class DictionaryStrategy:
    """
    Dictionary-based mutation strategy
    
    Uses a dictionary of tokens/keywords to insert into the input.
    Useful for format-specific fuzzing (JSON, XML, etc.)
    """
    
    def __init__(self, dictionary_path: Optional[str] = None):
        self.name = "dictionary"
        self.logger = get_logger()
        self.tokens: List[bytes] = []
        
        # Default tokens (common interesting values)
        self.default_tokens = [
            b'\x00',
            b'\xff',
            b'\x00\x00\x00\x00',
            b'\xff\xff\xff\xff',
            b'\x7f\xff\xff\xff',
            b'\x80\x00\x00\x00',
            b'%s',
            b'%n',
            b'%x',
            b'%p',
            b'%d' * 10,
            b'%s' * 10,
            b'AAAA',
            b'A' * 100,
            b'A' * 1000,
            b'../../../',
            b'..\\..\\..\\',
            b'<script>',
            b'</script>',
            b'<?xml',
            b'<!DOCTYPE',
            b'<!--',
            b'-->',
            b'<![CDATA[',
            b']]>',
            b'null',
            b'NULL',
            b'nil',
            b'None',
            b'undefined',
            b'NaN',
            b'Infinity',
            b'-Infinity',
            b'true',
            b'false',
            b'{}',
            b'[]',
            b'{{',
            b'}}',
            b'[[',
            b']]',
            b'"',
            b"'",
            b'`',
            b'\\',
            b'\\x00',
            b'\\u0000',
            b'\\n',
            b'\\r',
            b'\\t',
            b'\r\n',
            b'\n\r',
            b'\x00\x00',
            b'\x0a\x0d',
            b'0',
            b'-1',
            b'-2147483648',
            b'2147483647',
            b'4294967295',
            b'9999999999999999999',
            b'1e309',
            b'-1e309',
            b'0.0',
            b'-0.0',
            b'1.7976931348623157E+308',
        ]
        
        # Load dictionary if provided
        if dictionary_path:
            self.load(dictionary_path)
        else:
            self.tokens = self.default_tokens.copy()
    
    def load(self, dictionary_path: str) -> bool:
        """
        Load tokens from dictionary file
        
        Args:
            dictionary_path: Path to dictionary file
        
        Returns:
            True if loaded successfully
        """
        try:
            if not FileUtils.file_exists(dictionary_path):
                self.logger.warning(f"Dictionary not found: {dictionary_path}")
                self.tokens = self.default_tokens.copy()
                return False
            
            content = FileUtils.read_text(dictionary_path)
            
            self.tokens = self.default_tokens.copy()
            
            for line in content.split('\n'):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle quoted strings
                if line.startswith('"') and line.endswith('"'):
                    line = line[1:-1]
                
                # Handle escape sequences
                try:
                    token = line.encode('utf-8').decode('unicode_escape').encode('utf-8')
                except:
                    token = line.encode('utf-8')
                
                if token and token not in self.tokens:
                    self.tokens.append(token)
            
            self.logger.info(f"Loaded {len(self.tokens)} tokens from dictionary")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load dictionary: {e}")
            self.tokens = self.default_tokens.copy()
            return False
    
    def mutate(self, data: bytearray) -> bytearray:
        """Apply dictionary-based mutation"""
        if len(self.tokens) == 0:
            return data
        
        mutation_type = random.choice([
            self._insert_token,
            self._overwrite_with_token,
            self._append_token,
            self._prepend_token,
        ])
        
        return mutation_type(data)
    
    def _insert_token(self, data: bytearray) -> bytearray:
        """Insert a random token at a random position"""
        token = random.choice(self.tokens)
        
        if len(data) == 0:
            return bytearray(token)
        
        insert_idx = random.randint(0, len(data))
        data[insert_idx:insert_idx] = token
        
        return data
    
    def _overwrite_with_token(self, data: bytearray) -> bytearray:
        """Overwrite data at a random position with a token"""
        if len(data) == 0:
            return data
        
        token = random.choice(self.tokens)
        
        start_idx = random.randint(0, max(0, len(data) - 1))
        end_idx = min(start_idx + len(token), len(data))
        
        data[start_idx:end_idx] = token[:end_idx - start_idx]
        
        return data
    
    def _append_token(self, data: bytearray) -> bytearray:
        """Append a token to the end"""
        token = random.choice(self.tokens)
        data.extend(token)
        return data
    
    def _prepend_token(self, data: bytearray) -> bytearray:
        """Prepend a token to the beginning"""
        token = random.choice(self.tokens)
        data[0:0] = token
        return data
    
    def add_token(self, token: bytes) -> None:
        """Add a new token to the dictionary"""
        if token not in self.tokens:
            self.tokens.append(token)
    
    def add_tokens(self, tokens: List[bytes]) -> None:
        """Add multiple tokens to the dictionary"""
        for token in tokens:
            self.add_token(token)
    
    def remove_token(self, token: bytes) -> bool:
        """Remove a token from the dictionary"""
        if token in self.tokens:
            self.tokens.remove(token)
            return True
        return False
    
    def clear(self) -> None:
        """Clear all tokens"""
        self.tokens = []
    
    def reset(self) -> None:
        """Reset to default tokens"""
        self.tokens = self.default_tokens.copy()
    
    def get_tokens(self) -> List[bytes]:
        """Get all tokens"""
        return self.tokens.copy()
    
    def save(self, path: str) -> bool:
        """Save dictionary to file"""
        try:
            lines = []
            for token in self.tokens:
                # Convert to escaped string representation
                escaped = token.decode('utf-8', errors='replace')
                lines.append(f'"{escaped}"')
            
            FileUtils.write_text(path, '\n'.join(lines))
            return True
        except Exception as e:
            self.logger.error(f"Failed to save dictionary: {e}")
            return False