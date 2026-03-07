"""
SOFuzz - APK Extractor
Extracts .so files from Android APK files
"""

import os
import zipfile
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.constants import (
    APK_LIB_DIR,
    SUPPORTED_ARCHS,
    SYSTEM_LIBS,
    DEFAULT_EXTRACTED_DIR
)


@dataclass
class ExtractedLibrary:
    """Represents an extracted .so library"""
    name: str
    path: str
    architecture: str
    size: int
    md5_hash: str


@dataclass
class APKInfo:
    """Information about an APK file"""
    name: str
    path: str
    size: int
    package_name: Optional[str] = None
    architectures: List[str] = field(default_factory=list)
    libraries: List[ExtractedLibrary] = field(default_factory=list)
    total_libs: int = 0


class APKExtractor:
    """
    Extracts native libraries (.so files) from Android APK files
    """
    
    def __init__(
        self,
        apk_path: str,
        output_dir: str = DEFAULT_EXTRACTED_DIR,
        preferred_archs: List[str] = None,
        skip_system_libs: bool = True
    ):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.preferred_archs = preferred_archs or SUPPORTED_ARCHS
        self.skip_system_libs = skip_system_libs
        self.logger = get_logger()
        
        if not FileUtils.file_exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        if not FileUtils.is_zip_file(apk_path):
            raise ValueError(f"Invalid APK file (not a ZIP): {apk_path}")
        
        self.apk_name = FileUtils.get_file_name(apk_path)
        self.extract_path = os.path.join(output_dir, self.apk_name)
        FileUtils.ensure_dir(self.extract_path)
    
    def extract(self) -> APKInfo:
        """Extract all .so files from APK"""
        self.logger.info(f"Extracting APK: {self.apk_path}")
        
        apk_info = APKInfo(
            name=self.apk_name,
            path=self.apk_path,
            size=FileUtils.get_file_size(self.apk_path)
        )
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                all_files = apk.namelist()
                so_files = self._find_so_files(all_files)
                
                if not so_files:
                    self.logger.warning("No native libraries found in APK")
                    return apk_info
                
                apk_info.architectures = self._get_architectures(so_files)
                self.logger.info(f"Found architectures: {apk_info.architectures}")
                
                for so_file in so_files:
                    lib = self._extract_library(apk, so_file)
                    if lib:
                        apk_info.libraries.append(lib)
                
                apk_info.total_libs = len(apk_info.libraries)
                self.logger.success(f"Extracted {apk_info.total_libs} libraries")
                
        except zipfile.BadZipFile as e:
            self.logger.error(f"Bad APK file: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Extraction failed: {e}")
            raise
        
        return apk_info
    
    def extract_best_arch(self) -> APKInfo:
        """Extract .so files only for the best available architecture"""
        self.logger.info(f"Extracting APK (best arch): {self.apk_path}")
        
        apk_info = APKInfo(
            name=self.apk_name,
            path=self.apk_path,
            size=FileUtils.get_file_size(self.apk_path)
        )
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                all_files = apk.namelist()
                so_files = self._find_so_files(all_files)
                
                if not so_files:
                    self.logger.warning("No native libraries found in APK")
                    return apk_info
                
                available_archs = self._get_architectures(so_files)
                best_arch = self._select_best_arch(available_archs)
                
                if not best_arch:
                    self.logger.error("No supported architecture found")
                    return apk_info
                
                self.logger.info(f"Selected architecture: {best_arch}")
                apk_info.architectures = [best_arch]
                
                for so_file in so_files:
                    if f"/{best_arch}/" in so_file:
                        lib = self._extract_library(apk, so_file)
                        if lib:
                            apk_info.libraries.append(lib)
                
                apk_info.total_libs = len(apk_info.libraries)
                self.logger.success(f"Extracted {apk_info.total_libs} libraries")
                
        except Exception as e:
            self.logger.error(f"Extraction failed: {e}")
            raise
        
        return apk_info
    
    def _find_so_files(self, file_list: List[str]) -> List[str]:
        """Find all .so files in the file list"""
        so_files = []
        
        for file_path in file_list:
            # Check if it's in lib/ directory and is a .so file
            if file_path.startswith(f"{APK_LIB_DIR}/") and FileUtils.is_so_file(file_path):
                lib_name = os.path.basename(file_path)
                
                # Skip system libraries if configured
                if self.skip_system_libs and lib_name in SYSTEM_LIBS:
                    continue
                
                so_files.append(file_path)
        
        return so_files
    
    def _get_architectures(self, so_files: List[str]) -> List[str]:
        """Get list of architectures from .so file paths"""
        archs = set()
        
        for so_file in so_files:
            parts = so_file.split('/')
            if len(parts) >= 2:
                arch = parts[1]  # lib/{arch}/libname.so
                if arch in SUPPORTED_ARCHS:
                    archs.add(arch)
        
        return list(archs)
    
    def _select_best_arch(self, available_archs: List[str]) -> Optional[str]:
        """Select the best architecture based on preference"""
        for arch in self.preferred_archs:
            if arch in available_archs:
                return arch
        return available_archs[0] if available_archs else None
    
    def _extract_library(self, apk: zipfile.ZipFile, so_path: str) -> Optional[ExtractedLibrary]:
        """Extract a single library from APK"""
        try:
            # Get architecture from path
            parts = so_path.split('/')
            arch = parts[1] if len(parts) >= 2 else "unknown"
            lib_name = os.path.basename(so_path)
            
            # Create architecture directory
            arch_dir = os.path.join(self.extract_path, arch)
            FileUtils.ensure_dir(arch_dir)
            
            # Extract file
            output_path = os.path.join(arch_dir, lib_name)
            
            with apk.open(so_path) as src:
                data = src.read()
                FileUtils.write_file(output_path, data)
            
            # Calculate hash
            md5_hash = FileUtils.calculate_hash(data)
            
            self.logger.debug(f"Extracted: {lib_name} ({arch})")
            
            return ExtractedLibrary(
                name=lib_name,
                path=output_path,
                architecture=arch,
                size=len(data),
                md5_hash=md5_hash
            )
            
        except Exception as e:
            self.logger.error(f"Failed to extract {so_path}: {e}")
            return None
    
    def get_library_paths(self, architecture: str = None) -> List[str]:
        """Get paths to all extracted libraries"""
        paths = []
        
        if architecture:
            arch_dir = os.path.join(self.extract_path, architecture)
            if FileUtils.dir_exists(arch_dir):
                paths = FileUtils.list_files(arch_dir, ".so")
        else:
            for arch in SUPPORTED_ARCHS:
                arch_dir = os.path.join(self.extract_path, arch)
                if FileUtils.dir_exists(arch_dir):
                    paths.extend(FileUtils.list_files(arch_dir, ".so"))
        
        return paths
    
    def list_contents(self) -> Dict[str, List[str]]:
        """List all .so files in APK without extracting"""
        contents = {}
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                all_files = apk.namelist()
                so_files = self._find_so_files(all_files)
                
                for so_file in so_files:
                    parts = so_file.split('/')
                    arch = parts[1] if len(parts) >= 2 else "unknown"
                    lib_name = os.path.basename(so_file)
                    
                    if arch not in contents:
                        contents[arch] = []
                    contents[arch].append(lib_name)
                    
        except Exception as e:
            self.logger.error(f"Failed to list APK contents: {e}")
        
        return contents
    
    def cleanup(self) -> None:
        """Remove extracted files"""
        if FileUtils.dir_exists(self.extract_path):
            FileUtils.delete_dir(self.extract_path)
            self.logger.info(f"Cleaned up: {self.extract_path}")