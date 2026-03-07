"""
SOFuzz - Constants and Configuration Values
"""

import os
from enum import Enum, IntEnum
from typing import List, Dict

# =============================================================================
# PROJECT INFO
# =============================================================================

PROJECT_NAME = "SOFuzz"
VERSION = "1.0.0"

# =============================================================================
# PATHS
# =============================================================================

# Get project root directory
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Default directories
DEFAULT_OUTPUT_DIR = os.path.join(ROOT_DIR, "output")
DEFAULT_EXTRACTED_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "extracted")
DEFAULT_ANALYSIS_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "analysis")
DEFAULT_HARNESS_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "harnesses")
DEFAULT_CRASH_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "crashes")
DEFAULT_COVERAGE_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "coverage")
DEFAULT_REPORT_DIR = os.path.join(DEFAULT_OUTPUT_DIR, "reports")
DEFAULT_SEEDS_DIR = os.path.join(ROOT_DIR, "data", "seeds")
DEFAULT_DICT_DIR = os.path.join(ROOT_DIR, "data", "dictionaries")

# =============================================================================
# ELF CONSTANTS
# =============================================================================

# ELF Magic bytes
ELF_MAGIC = b'\x7fELF'

# ELF Class (32-bit or 64-bit)
class ELFClass(IntEnum):
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2

# ELF Data encoding (endianness)
class ELFData(IntEnum):
    ELFDATANONE = 0
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian

# ELF File types
class ELFType(IntEnum):
    ET_NONE = 0      # No file type
    ET_REL = 1       # Relocatable file
    ET_EXEC = 2      # Executable file
    ET_DYN = 3       # Shared object file (.so)
    ET_CORE = 4      # Core file

# ELF Machine types (architectures)
class ELFMachine(IntEnum):
    EM_NONE = 0
    EM_386 = 3       # Intel 80386 (x86)
    EM_ARM = 40      # ARM
    EM_X86_64 = 62   # AMD x86-64
    EM_AARCH64 = 183 # ARM 64-bit (AArch64)

# Machine type to string mapping
MACHINE_NAMES: Dict[int, str] = {
    0: "None",
    3: "x86 (i386)",
    40: "ARM",
    62: "x86_64",
    183: "ARM64 (AArch64)",
}

# Section types
class SectionType(IntEnum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15

# Symbol types
class SymbolType(IntEnum):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6

# Symbol binding
class SymbolBinding(IntEnum):
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2

# =============================================================================
# ANDROID / APK CONSTANTS
# =============================================================================

# APK lib directory structure
APK_LIB_DIR = "lib"

# Supported architectures (in order of preference for x86 systems)
SUPPORTED_ARCHS: List[str] = [
    "x86_64",
    "x86",
    "arm64-v8a",
    "armeabi-v7a",
    "armeabi",
]

# Architecture to ELF machine mapping
ARCH_TO_MACHINE: Dict[str, int] = {
    "x86_64": 62,
    "x86": 3,
    "arm64-v8a": 183,
    "armeabi-v7a": 40,
    "armeabi": 40,
}

# System libraries to skip
SYSTEM_LIBS: List[str] = [
    "libc.so",
    "libm.so",
    "libdl.so",
    "liblog.so",
    "libz.so",
    "libstdc++.so",
    "libandroid.so",
    "libEGL.so",
    "libGLESv2.so",
    "libOpenSLES.so",
    "libjnigraphics.so",
    "libmediandk.so",
    "libcamera2ndk.so",
    "libnativewindow.so",
    "libsync.so",
    "libvulkan.so",
    "libaaudio.so",
    "libamidi.so",
]

# =============================================================================
# FUZZING CONSTANTS
# =============================================================================

# Function prefixes to skip during fuzzing
SKIP_FUNCTION_PREFIXES: List[str] = [
    "_init",
    "_fini",
    "__cxa_",
    "__gxx_",
    "_ITM_",
    "_Jv_",
    "frame_dummy",
    "__do_global",
    "__libc_",
    "__aeabi_",
    "__gnu_",
    "register_tm",
    "deregister_tm",
]

# Interesting values for fuzzing (8-bit)
INTERESTING_8: List[int] = [
    0,          # Zero
    1,          # One
    16,         # One-off with common block size
    32,         # One-off with common block size
    64,         # One-off with common block size
    100,        # One-off with common block size
    127,        # Signed 8-bit max
    128,        # Signed 8-bit overflow
    255,        # Unsigned 8-bit max
]

# Interesting values for fuzzing (16-bit)
INTERESTING_16: List[int] = [
    0,          # Zero
    1,          # One
    128,        # Signed 8-bit boundary
    255,        # Unsigned 8-bit max
    256,        # Unsigned 8-bit overflow
    512,        # Common block size
    1000,       # Common value
    1024,       # Common block size
    4096,       # Common page size
    32767,      # Signed 16-bit max
    32768,      # Signed 16-bit overflow
    65535,      # Unsigned 16-bit max
]

# Interesting values for fuzzing (32-bit)
INTERESTING_32: List[int] = [
    0,           # Zero
    1,           # One
    32768,       # Signed 16-bit boundary
    65535,       # Unsigned 16-bit max
    65536,       # Unsigned 16-bit overflow
    100663046,   # Large positive
    2147483647,  # Signed 32-bit max
    2147483648,  # Signed 32-bit overflow
    4294967295,  # Unsigned 32-bit max
]

# Interesting values for fuzzing (64-bit)
INTERESTING_64: List[int] = [
    0,
    1,
    4294967295,          # Unsigned 32-bit max
    4294967296,          # Unsigned 32-bit overflow
    9223372036854775807, # Signed 64-bit max
]

# =============================================================================
# CRASH SIGNALS
# =============================================================================

class CrashSignal(IntEnum):
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGBUS = 7
    SIGFPE = 8
    SIGKILL = 9
    SIGUSR1 = 10
    SIGSEGV = 11
    SIGUSR2 = 12
    SIGPIPE = 13
    SIGALRM = 14
    SIGTERM = 15

# Signals that indicate a crash
CRASH_SIGNALS: List[int] = [
    4,   # SIGILL - Illegal instruction
    6,   # SIGABRT - Abort
    7,   # SIGBUS - Bus error
    8,   # SIGFPE - Floating point exception
    11,  # SIGSEGV - Segmentation fault
]

# Signal names
SIGNAL_NAMES: Dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}

# =============================================================================
# CRASH SEVERITY
# =============================================================================

class CrashSeverity(Enum):
    CRITICAL = "CRITICAL"  # Exploitable (buffer overflow, use-after-free)
    HIGH = "HIGH"          # Memory corruption
    MEDIUM = "MEDIUM"      # Null pointer dereference
    LOW = "LOW"            # Assertion failure, timeout
    UNKNOWN = "UNKNOWN"    # Unknown crash type

# =============================================================================
# DEFAULT VALUES
# =============================================================================

# Fuzzer defaults
DEFAULT_TIMEOUT = 2          # seconds
DEFAULT_MAX_ITERATIONS = 100000
DEFAULT_MAX_TIME = 3600      # 1 hour
DEFAULT_MAX_INPUT_SIZE = 1024 * 1024  # 1 MB
DEFAULT_MIN_INPUT_SIZE = 1
DEFAULT_NUM_WORKERS = 1

# Mutator defaults
DEFAULT_MAX_MUTATIONS = 10
DEFAULT_MUTATION_RATE = 0.1

# Crash handler defaults
DEFAULT_MAX_CRASHES = 1000

# =============================================================================
# COLORS (for terminal output)
# =============================================================================

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"