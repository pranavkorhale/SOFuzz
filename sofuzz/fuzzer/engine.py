"""
SOFuzz - Main Fuzzer Engine
"""

import os
import time
import random
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_MAX_INPUT_SIZE,
    DEFAULT_CRASH_DIR
)
from ..mutator.mutator import Mutator
from ..crash.detector import CrashDetector
from ..crash.deduplicator import CrashDeduplicator
from .executor import Executor, ExecutionResult
from .queue import InputQueue
from .scheduler import Scheduler


@dataclass
class FuzzerStats:
    """Fuzzer statistics"""
    start_time: float = 0
    iterations: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    executions_per_second: float = 0
    last_crash_time: float = 0
    coverage: float = 0


@dataclass
class FuzzerConfig:
    """Fuzzer configuration"""
    target_binary: str
    seed_dir: Optional[str] = None
    crash_dir: str = DEFAULT_CRASH_DIR
    max_iterations: int = DEFAULT_MAX_ITERATIONS
    max_time: int = 0
    timeout: float = DEFAULT_TIMEOUT
    max_input_size: int = DEFAULT_MAX_INPUT_SIZE
    use_stdin: bool = True


class FuzzerEngine:
    """
    Main fuzzing engine
    """
    
    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.logger = get_logger()
        
        self.mutator = Mutator()
        self.executor = Executor(
            binary_path=config.target_binary,
            timeout=config.timeout,
            use_stdin=config.use_stdin
        )
        self.queue = InputQueue()
        self.scheduler = Scheduler()
        self.crash_detector = CrashDetector()
        self.deduplicator = CrashDeduplicator()
        
        self.stats = FuzzerStats()
        
        self.crash_dir = config.crash_dir
        FileUtils.ensure_dir(self.crash_dir)
        
        self.running = False
        self.paused = False
        
        self.on_crash: Optional[Callable] = None
        self.on_iteration: Optional[Callable] = None
    
    def load_seeds(self, seed_dir: str = None) -> int:
        """Load seed files"""
        seed_dir = seed_dir or self.config.seed_dir
        
        if not seed_dir or not FileUtils.dir_exists(seed_dir):
            self.logger.warning("No seeds found, using default seed")
            self.queue.add(b'\x00' * 10)
            return 1
        
        count = 0
        for file_path in FileUtils.list_files(seed_dir):
            try:
                data = FileUtils.read_file(file_path)
                
                if len(data) > self.config.max_input_size:
                    data = data[:self.config.max_input_size]
                
                self.queue.add(data)
                count += 1
                
            except Exception as e:
                self.logger.debug(f"Failed to load seed {file_path}: {e}")
        
        self.logger.info(f"Loaded {count} seeds")
        return count
    
    def run(self) -> FuzzerStats:
        """Run the fuzzer"""
        self.logger.banner()
        self.logger.info(f"Starting fuzzer")
        self.logger.info(f"Target: {self.config.target_binary}")
        self.logger.info(f"Max iterations: {self.config.max_iterations}")
        
        self.load_seeds()
        
        self.stats = FuzzerStats()
        self.stats.start_time = time.time()
        self.running = True
        
        try:
            self._fuzzing_loop()
        except KeyboardInterrupt:
            self.logger.warning("Fuzzing interrupted by user")
        finally:
            self.running = False
        
        self._calculate_stats()
        self._print_final_stats()
        
        return self.stats
    
    def _fuzzing_loop(self) -> None:
        """Main fuzzing loop"""
        last_status_time = time.time()
        status_interval = 5
        
        while self.running:
            if self._should_stop():
                break
            
            if self.paused:
                time.sleep(0.1)
                continue
            
            seed = self.scheduler.select(self.queue)
            
            if seed is None:
                seed = b'\x00' * 10
            
            mutated = self.mutator.mutate(seed)
            result = self.executor.execute(mutated)
            
            self.stats.iterations += 1
            
            if result.is_crash:
                self._handle_crash(mutated, result)
            
            if result.timed_out:
                self.stats.timeouts += 1
            
            if self._is_interesting(result):
                self.queue.add(mutated)
            
            if self.on_iteration:
                self.on_iteration(self.stats.iterations, result)
            
            if time.time() - last_status_time >= status_interval:
                self._print_status()
                last_status_time = time.time()
    
    def _should_stop(self) -> bool:
        """Check if fuzzing should stop"""
        if self.config.max_iterations > 0:
            if self.stats.iterations >= self.config.max_iterations:
                return True
        
        if self.config.max_time > 0:
            elapsed = time.time() - self.stats.start_time
            if elapsed >= self.config.max_time:
                return True
        
        return False
    
    def _handle_crash(self, input_data: bytes, result: ExecutionResult) -> None:
        """Handle a crash"""
        self.stats.crashes += 1
        self.stats.last_crash_time = time.time()
        
        crash_hash = self.deduplicator.get_hash(input_data, result)
        
        if self.deduplicator.is_unique(crash_hash):
            self.stats.unique_crashes += 1
            self.deduplicator.add(crash_hash)
            
            # Save crash
            self._save_crash(input_data, result, crash_hash)
            
            self.logger.error(f"[!] CRASH #{self.stats.unique_crashes}: {result.signal_name}")
            
            # Callback
            if self.on_crash:
                self.on_crash(input_data, result)
    
    def _save_crash(self, input_data: bytes, result: ExecutionResult, crash_hash: str) -> str:
        """Save crash to disk"""
        # Create crash directory
        crash_id = f"crash_{self.stats.unique_crashes:04d}_{crash_hash[:8]}"
        crash_path = os.path.join(self.crash_dir, crash_id)
        FileUtils.ensure_dir(crash_path)
        
        # Save input
        input_path = os.path.join(crash_path, "input.bin")
        FileUtils.write_file(input_path, input_data)
        
        # Save crash info
        info = f"""Crash Information
==================
ID: {crash_id}
Hash: {crash_hash}
Signal: {result.signal_name}
Return Code: {result.returncode}
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
Input Size: {len(input_data)} bytes

Stderr:
{result.stderr.decode('utf-8', errors='ignore')}

Stdout:
{result.stdout.decode('utf-8', errors='ignore')}
"""
        info_path = os.path.join(crash_path, "info.txt")
        FileUtils.write_text(info_path, info)
        
        return crash_path
    
    def _is_interesting(self, result: ExecutionResult) -> bool:
        """Check if result is interesting (for coverage)"""
        # For now, just return False (no coverage tracking)
        # Can be extended with coverage-guided logic
        return False
    
    def _calculate_stats(self) -> None:
        """Calculate final statistics"""
        elapsed = time.time() - self.stats.start_time
        if elapsed > 0:
            self.stats.executions_per_second = self.stats.iterations / elapsed
    
    def _print_status(self) -> None:
        """Print current status"""
        elapsed = time.time() - self.stats.start_time
        
        if elapsed > 0:
            exec_per_sec = self.stats.iterations / elapsed
        else:
            exec_per_sec = 0
        
        self.logger.info(
            f"[{elapsed:.1f}s] "
            f"iterations: {self.stats.iterations} | "
            f"crashes: {self.stats.unique_crashes} | "
            f"timeouts: {self.stats.timeouts} | "
            f"speed: {exec_per_sec:.1f}/s"
        )
    
    def _print_final_stats(self) -> None:
        """Print final statistics"""
        elapsed = time.time() - self.stats.start_time
        
        stats_dict = {
            "Total Time": f"{elapsed:.2f} seconds",
            "Iterations": self.stats.iterations,
            "Total Crashes": self.stats.crashes,
            "Unique Crashes": self.stats.unique_crashes,
            "Timeouts": self.stats.timeouts,
            "Exec/Second": f"{self.stats.executions_per_second:.2f}",
            "Crash Directory": self.crash_dir,
        }
        
        self.logger.stats(stats_dict)
    
    def stop(self) -> None:
        """Stop the fuzzer"""
        self.running = False
    
    def pause(self) -> None:
        """Pause the fuzzer"""
        self.paused = True
    
    def resume(self) -> None:
        """Resume the fuzzer"""
        self.paused = False
    
    def get_stats(self) -> FuzzerStats:
        """Get current statistics"""
        self._calculate_stats()
        return self.stats