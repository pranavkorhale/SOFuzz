"""
SOFuzz - Coverage Tracking
"""

import os
import hashlib
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils


@dataclass
class CoverageInfo:
    """Coverage information for an execution"""
    edge_count: int = 0
    block_count: int = 0
    path_hash: str = ""
    new_coverage: bool = False
    new_edges: int = 0
    new_blocks: int = 0


class CoverageTracker:
    """
    Tracks code coverage during fuzzing
    
    Note: This is a simplified coverage tracker.
    For real coverage-guided fuzzing, you would need
    instrumentation (like AFL's or libFuzzer's).
    
    This implementation uses output-based heuristics
    to estimate coverage when instrumentation is not available.
    
    Usage:
        tracker = CoverageTracker()
        
        # After execution
        cov_info = tracker.record(result)
        
        if cov_info.new_coverage:
            print("New coverage found!")
    """
    
    def __init__(self):
        self.logger = get_logger()
        
        # Seen paths (hashes of execution traces)
        self.seen_paths: Set[str] = set()
        
        # Seen edges (simplified - based on output)
        self.seen_edges: Set[str] = set()
        
        # Seen blocks
        self.seen_blocks: Set[str] = set()
        
        # Coverage bitmap (like AFL)
        self.bitmap: bytearray = bytearray(65536)
        
        # Statistics
        self.total_executions = 0
        self.unique_paths = 0
        self.unique_edges = 0
    
    def record(self, stdout: bytes, stderr: bytes, returncode: int) -> CoverageInfo:
        """
        Record coverage from execution
        
        Args:
            stdout: Standard output
            stderr: Standard error
            returncode: Return code
        
        Returns:
            CoverageInfo with coverage details
        """
        self.total_executions += 1
        
        info = CoverageInfo()
        
        # Create path hash from outputs
        path_data = stdout + stderr + str(returncode).encode()
        path_hash = hashlib.md5(path_data).hexdigest()
        info.path_hash = path_hash
        
        # Check for new path
        if path_hash not in self.seen_paths:
            self.seen_paths.add(path_hash)
            self.unique_paths += 1
            info.new_coverage = True
        
        # Estimate edge coverage from output
        edges = self._extract_edges(stdout, stderr)
        
        new_edge_count = 0
        for edge in edges:
            if edge not in self.seen_edges:
                self.seen_edges.add(edge)
                self.unique_edges += 1
                new_edge_count += 1
        
        info.new_edges = new_edge_count
        info.edge_count = len(edges)
        
        if new_edge_count > 0:
            info.new_coverage = True
        
        return info
    
    def _extract_edges(self, stdout: bytes, stderr: bytes) -> List[str]:
        """
        Extract edge hashes from output
        
        This is a heuristic approach - real coverage
        requires instrumentation.
        """
        edges = []
        
        # Use line-based hashing as a simple heuristic
        combined = stdout + stderr
        
        lines = combined.split(b'\n')
        
        prev_hash = "START"
        for line in lines:
            if line.strip():
                line_hash = hashlib.md5(line).hexdigest()[:8]
                edge = f"{prev_hash}->{line_hash}"
                edges.append(edge)
                prev_hash = line_hash
        
        return edges
    
    def update_bitmap(self, edge_id: int, hit_count: int = 1) -> bool:
        """
        Update coverage bitmap (AFL-style)
        
        Args:
            edge_id: Edge identifier
            hit_count: Number of hits
        
        Returns:
            True if new coverage
        """
        idx = edge_id % len(self.bitmap)
        
        # Classify hit count (AFL-style buckets)
        bucket = self._classify_count(hit_count)
        
        old_val = self.bitmap[idx]
        new_val = old_val | bucket
        
        if new_val != old_val:
            self.bitmap[idx] = new_val
            return True
        
        return False
    
    def _classify_count(self, count: int) -> int:
        """Classify hit count into buckets (AFL-style)"""
        if count == 0:
            return 0
        elif count == 1:
            return 1
        elif count == 2:
            return 2
        elif count == 3:
            return 4
        elif count <= 7:
            return 8
        elif count <= 15:
            return 16
        elif count <= 31:
            return 32
        elif count <= 127:
            return 64
        else:
            return 128
    
    def has_new_coverage(self, path_hash: str) -> bool:
        """Check if path hash is new"""
        return path_hash not in self.seen_paths
    
    def get_coverage_percent(self, total_edges: int = 0) -> float:
        """
        Get coverage percentage
        
        Args:
            total_edges: Total possible edges (if known)
        
        Returns:
            Coverage percentage
        """
        if total_edges > 0:
            return (len(self.seen_edges) / total_edges) * 100
        
        # Estimate based on bitmap
        covered = sum(1 for b in self.bitmap if b != 0)
        return (covered / len(self.bitmap)) * 100
    
    def get_stats(self) -> Dict:
        """Get coverage statistics"""
        return {
            'total_executions': self.total_executions,
            'unique_paths': self.unique_paths,
            'unique_edges': self.unique_edges,
            'bitmap_density': sum(1 for b in self.bitmap if b != 0),
        }
    
    def reset(self) -> None:
        """Reset coverage tracking"""
        self.seen_paths.clear()
        self.seen_edges.clear()
        self.seen_blocks.clear()
        self.bitmap = bytearray(65536)
        self.total_executions = 0
        self.unique_paths = 0
        self.unique_edges = 0
    
    def save(self, path: str) -> None:
        """Save coverage data to file"""
        data = {
            'paths': list(self.seen_paths),
            'edges': list(self.seen_edges),
            'stats': self.get_stats(),
        }
        FileUtils.write_json(path, data)
    
    def load(self, path: str) -> None:
        """Load coverage data from file"""
        if not FileUtils.file_exists(path):
            return
        
        data = FileUtils.read_json(path)
        
        self.seen_paths = set(data.get('paths', []))
        self.seen_edges = set(data.get('edges', []))
        
        stats = data.get('stats', {})
        self.unique_paths = stats.get('unique_paths', len(self.seen_paths))
        self.unique_edges = stats.get('unique_edges', len(self.seen_edges))