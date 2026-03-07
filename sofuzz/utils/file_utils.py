"""
SOFuzz - File Utilities
"""

import os
import shutil
import hashlib
import zipfile
import json
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any


class FileUtils:
    
    @staticmethod
    def ensure_dir(path: str) -> str:
        os.makedirs(path, exist_ok=True)
        return path
    
    @staticmethod
    def file_exists(path: str) -> bool:
        return os.path.isfile(path)
    
    @staticmethod
    def dir_exists(path: str) -> bool:
        return os.path.isdir(path)
    
    @staticmethod
    def get_file_size(path: str) -> int:
        return os.path.getsize(path)
    
    @staticmethod
    def get_file_extension(path: str) -> str:
        return os.path.splitext(path)[1].lower()
    
    @staticmethod
    def get_file_name(path: str) -> str:
        return os.path.splitext(os.path.basename(path))[0]
    
    @staticmethod
    def get_file_basename(path: str) -> str:
        return os.path.basename(path)
    
    @staticmethod
    def read_file(path: str) -> bytes:
        with open(path, 'rb') as f:
            return f.read()
    
    @staticmethod
    def write_file(path: str, data: bytes) -> None:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def read_text(path: str, encoding: str = 'utf-8') -> str:
        with open(path, 'r', encoding=encoding) as f:
            return f.read()
    
    @staticmethod
    def write_text(path: str, text: str, encoding: str = 'utf-8') -> None:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, 'w', encoding=encoding) as f:
            f.write(text)
    
    @staticmethod
    def read_json(path: str) -> Dict[str, Any]:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    @staticmethod
    def write_json(path: str, data: Dict[str, Any], indent: int = 2) -> None:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent)
    
    @staticmethod
    def copy_file(src: str, dst: str) -> str:
        dir_path = os.path.dirname(dst)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        shutil.copy2(src, dst)
        return dst
    
    @staticmethod
    def move_file(src: str, dst: str) -> str:
        dir_path = os.path.dirname(dst)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        shutil.move(src, dst)
        return dst
    
    @staticmethod
    def delete_file(path: str) -> bool:
        try:
            os.remove(path)
            return True
        except OSError:
            return False
    
    @staticmethod
    def delete_dir(path: str) -> bool:
        try:
            shutil.rmtree(path)
            return True
        except OSError:
            return False
    
    @staticmethod
    def list_files(directory: str, extension: Optional[str] = None) -> List[str]:
        files = []
        if not os.path.exists(directory):
            return files
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path):
                if extension is None or item.endswith(extension):
                    files.append(item_path)
        return files
    
    @staticmethod
    def list_dirs(directory: str) -> List[str]:
        dirs = []
        if not os.path.exists(directory):
            return dirs
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path):
                dirs.append(item_path)
        return dirs
    
    @staticmethod
    def find_files(directory: str, pattern: str) -> List[str]:
        from glob import glob
        return glob(os.path.join(directory, "**", pattern), recursive=True)
    
    @staticmethod
    def calculate_md5(path: str) -> str:
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    @staticmethod
    def calculate_sha256(path: str) -> str:
        hash_sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    @staticmethod
    def calculate_hash(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def is_zip_file(path: str) -> bool:
        return zipfile.is_zipfile(path)
    
    @staticmethod
    def extract_zip(zip_path: str, extract_to: str) -> List[str]:
        os.makedirs(extract_to, exist_ok=True)
        extracted_files = []
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
            extracted_files = zip_ref.namelist()
        return extracted_files
    
    @staticmethod
    def is_elf_file(path: str) -> bool:
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except:
            return False
    
    @staticmethod
    def is_so_file(path: str) -> bool:
        return path.endswith('.so') or '.so.' in path
    
    @staticmethod
    def get_temp_path(prefix: str = "sofuzz_", suffix: str = "") -> str:
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        os.close(fd)
        return path
    
    @staticmethod
    def get_temp_dir(prefix: str = "sofuzz_") -> str:
        return tempfile.mkdtemp(prefix=prefix)
