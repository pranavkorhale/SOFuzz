"""
SOFuzz - Logging Utility
"""

import os
import sys
import logging
from datetime import datetime
from typing import Optional

from .constants import Colors, PROJECT_NAME, DEFAULT_OUTPUT_DIR


class ColorFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    COLORS = {
        'DEBUG': Colors.CYAN,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.MAGENTA,
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Colors.RESET}"
        return super().format(record)


class Logger:
    """
    Logger class for SOFuzz
    """
    
    _instance: Optional['Logger'] = None
    _initialized: bool = False
    
    def __new__(cls, name: str = PROJECT_NAME, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(
        self,
        name: str = PROJECT_NAME,
        level: str = "INFO",
        log_file: Optional[str] = None,
        use_colors: bool = True
    ):
        if Logger._initialized:
            return
        
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers = []
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        
        if use_colors:
            console_format = ColorFormatter(f"[%(levelname)s] %(message)s")
        else:
            console_format = logging.Formatter(f"[%(levelname)s] %(message)s")
        
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
        
        Logger._initialized = True
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)
    
    def success(self, message: str):
        self.logger.info(f"{Colors.GREEN}✓ {message}{Colors.RESET}")
    
    def failure(self, message: str):
        self.logger.error(f"{Colors.RED}✗ {message}{Colors.RESET}")
    
    def banner(self):
        """Print SOFuzz banner"""
        banner = f"""
{Colors.CYAN}
  ███████╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ██╔════╝██╔═══██╗██╔════╝██║   ██║╚══███╔╝╚══███╔╝
  ███████╗██║   ██║█████╗  ██║   ██║  ███╔╝   ███╔╝ 
  ╚════██║██║   ██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
  ███████║╚██████╔╝██║     ╚██████╔╝███████╗███████╗
  ╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝
{Colors.RESET}
  {Colors.YELLOW}Smart Fuzzer for Android Native Libraries{Colors.RESET}
  {Colors.WHITE}Version: 1.0.0{Colors.RESET}
"""
        print(banner)
    
    def progress(self, current: int, total: int, prefix: str = "", suffix: str = ""):
        """Print progress bar"""
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        percent = f"{100 * current / total:.1f}"
        print(f"\r{prefix} |{Colors.CYAN}{bar}{Colors.RESET}| {percent}% {suffix}", end="", flush=True)
        if current == total:
            print()
    
    def stats(self, stats_dict: dict):
        """Print statistics"""
        print(f"\n{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(f"{Colors.BOLD}Statistics:{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        for key, value in stats_dict.items():
            print(f"  {Colors.WHITE}{key}:{Colors.RESET} {value}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}\n")


def get_logger(name: str = PROJECT_NAME) -> Logger:
    """Get logger instance"""
    return Logger(name)