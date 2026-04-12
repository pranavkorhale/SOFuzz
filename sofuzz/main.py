#!/usr/bin/env python3
"""
SOFuzz - Main Entry Point
Smart Fuzzer for Android Native Libraries (.so files)
"""

import os
import sys
import argparse
import time
from typing import Optional, List

from .utils.logger import Logger, get_logger
from .utils.file_utils import FileUtils
from .utils.constants import (
    PROJECT_NAME,
    VERSION,
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_CRASH_DIR,
    DEFAULT_REPORT_DIR,
    DEFAULT_SEEDS_DIR,
)

from .extractor.apk_extractor import APKExtractor
from .analyzer.function_analyzer import FunctionAnalyzer
from .harness.generator import HarnessGenerator
from .harness.compiler import HarnessCompiler
from .fuzzer.engine import FuzzerEngine, FuzzerConfig
from .crash.analyzer import CrashAnalyzer
from .reporter.reporter import Reporter


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog='sofuzz',
        description='SOFuzz - Smart Fuzzer for Android Native Libraries (.so files)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz a .so file directly
  sofuzz --target libnative.so
  
  # Extract and fuzz from APK
  sofuzz --apk app.apk
  
  # Fuzz specific function
  sofuzz --target libnative.so --function parse_data
  
  # Analyze only (no fuzzing)
  sofuzz --target libnative.so --analyze-only
  
  # Set custom options
  sofuzz --target libnative.so --timeout 5 --iterations 50000
"""
    )
    
    # Main input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '-t', '--target',
        help='Path to target .so file'
    )
    input_group.add_argument(
        '-a', '--apk',
        help='Path to APK file (will extract .so files)'
    )
    input_group.add_argument(
        '-f', '--function',
        help='Specific function to fuzz'
    )
    
    # Fuzzing options
    fuzz_group = parser.add_argument_group('Fuzzing Options')
    fuzz_group.add_argument(
        '--timeout',
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f'Execution timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    fuzz_group.add_argument(
        '--iterations',
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        help=f'Maximum iterations (default: {DEFAULT_MAX_ITERATIONS})'
    )
    fuzz_group.add_argument(
        '--max-time',
        type=int,
        default=0,
        help='Maximum fuzzing time in seconds (0 = unlimited)'
    )
    fuzz_group.add_argument(
        '--seeds',
        help='Path to seed directory'
    )
    fuzz_group.add_argument(
        '--dictionary',
        help='Path to dictionary file'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        default='output',
        help='Output directory (default: output)'
    )
    output_group.add_argument(
        '--crash-dir',
        help='Crash output directory'
    )
    output_group.add_argument(
        '--report-dir',
        help='Report output directory'
    )
    
    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument(
        '--analyze-only',
        action='store_true',
        help='Only analyze target, do not fuzz'
    )
    analysis_group.add_argument(
        '--list-functions',
        action='store_true',
        help='List all fuzzable functions'
    )
    analysis_group.add_argument(
        '--generate-harness',
        action='store_true',
        help='Generate harness only, do not fuzz'
    )
    
    # Other options
    other_group = parser.add_argument_group('Other Options')
    other_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    other_group.add_argument(
        '--version',
        action='version',
        version=f'{PROJECT_NAME} {VERSION}'
    )
    
    return parser.parse_args()


def extract_from_apk(apk_path: str, output_dir: str) -> List[str]:
    """Extract .so files from APK"""
    logger = get_logger()
    logger.info(f"Extracting .so files from APK: {apk_path}")
    
    extractor = APKExtractor(apk_path, output_dir=output_dir)
    result = extractor.extract_best_arch()
    
    # Run Phase 1 Native Fingerprinting
    getattr(extractor, 'generate_fingerprint')()
    
    so_files = []
    for lib in result.libraries:
        so_files.append(lib.path)
        logger.info(f"  Extracted: {lib.name} ({lib.architecture})")
    
    return so_files


def analyze_target(so_path: str) -> None:
    """Analyze a .so file"""
    logger = get_logger()
    logger.info(f"Analyzing: {so_path}")
    
    analyzer = FunctionAnalyzer(so_path)
    analyzer.print_analysis()


def list_functions(so_path: str) -> None:
    """List fuzzable functions in .so file"""
    logger = get_logger()
    logger.info(f"Listing functions in: {so_path}")
    
    analyzer = FunctionAnalyzer(so_path)
    result = analyzer.analyze()
    
    print(f"\nFuzzable Functions ({result.fuzzable_count}):")
    print("-" * 60)
    
    for func in result.fuzzable_functions:
        jni_marker = "[JNI] " if func.is_jni else ""
        print(f"  {jni_marker}{func.name}")
        print(f"    Address: 0x{func.address:x}, Size: {func.size}, Risk: {func.risk_score}")


def generate_harness(so_path: str, output_dir: str, function_name: str = None) -> List[str]:
    """Generate fuzzing harnesses"""
    logger = get_logger()
    
    analyzer = FunctionAnalyzer(so_path)
    result = analyzer.analyze()
    
    if function_name:
        functions = [f for f in result.fuzzable_functions if f.name == function_name]
        if not functions:
            logger.error(f"Function not found: {function_name}")
            return []
    else:
        functions = result.fuzzable_functions
    
    generator = HarnessGenerator(so_path, output_dir=output_dir)
    harnesses = generator.generate_for_all(functions)
    
    compiler = HarnessCompiler()
    source_paths = [h.source_path for h in harnesses if h.is_generated]
    compile_results = compiler.compile_all(source_paths)
    
    binaries = []
    for result in compile_results:
        if result.success:
            binaries.append(result.binary_path)
    
    return binaries


def fuzz_target(
    target_binary: str,
    seed_dir: str = None,
    crash_dir: str = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_time: int = 0
) -> None:
    """Fuzz a target binary"""
    logger = get_logger()
    
    config = FuzzerConfig(
        target_binary=target_binary,
        seed_dir=seed_dir,
        crash_dir=crash_dir or DEFAULT_CRASH_DIR,
        timeout=timeout,
        max_iterations=max_iterations,
        max_time=max_time
    )
    
    fuzzer = FuzzerEngine(config)
    stats = fuzzer.run()
    
    crash_analyzer = CrashAnalyzer(crash_dir=config.crash_dir)
    crashes = crash_analyzer.analyze_crash_dir()
    
    reporter = Reporter()
    target_name = FileUtils.get_file_name(target_binary)
    reporter.generate(stats, crashes, target_name, target_binary)


def main():
    """Main entry point"""
    args = parse_args()
    
    # Initialize logger
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = Logger(level=log_level)
    logger.banner()
    
    # Validate input
    if not args.target and not args.apk:
        logger.error("Please specify --target or --apk")
        sys.exit(1)
    
    # Setup directories
    output_dir = args.output
    crash_dir = args.crash_dir or os.path.join(output_dir, "crashes")
    report_dir = args.report_dir or os.path.join(output_dir, "reports")
    harness_dir = os.path.join(output_dir, "harnesses")
    extracted_dir = os.path.join(output_dir, "extracted")
    
    FileUtils.ensure_dir(output_dir)
    FileUtils.ensure_dir(crash_dir)
    FileUtils.ensure_dir(report_dir)
    
    try:
        # Extract from APK if specified
        so_files = []
        if args.apk:
            so_files = extract_from_apk(args.apk, extracted_dir)
            if not so_files:
                logger.error("No .so files found in APK")
                sys.exit(1)
        elif args.target:
            so_files = [args.target]
        
        # Process each .so file
        for so_path in so_files:
            logger.info(f"\nProcessing: {so_path}")
            
            # Analyze only
            if args.analyze_only:
                analyze_target(so_path)
                continue
            
            # List functions only
            if args.list_functions:
                list_functions(so_path)
                continue
            
            # Generate harness
            if args.generate_harness:
                binaries = generate_harness(so_path, harness_dir, args.function)
                logger.success(f"Generated {len(binaries)} harnesses")
                for binary in binaries:
                    logger.info(f"  {binary}")
                continue
            
            # Full fuzzing workflow
            logger.info("Starting full fuzzing workflow...")
            
            # 1. Analyze
            logger.info("Step 1: Analyzing target...")
            analyzer = FunctionAnalyzer(so_path)
            result = analyzer.analyze()
            
            if result.fuzzable_count == 0:
                logger.warning("No fuzzable functions found")
                continue
            
            logger.info(f"Found {result.fuzzable_count} fuzzable functions")
            
            # 2. Generate harnesses
            logger.info("Step 2: Generating harnesses...")
            binaries = generate_harness(so_path, harness_dir, args.function)
            
            if not binaries:
                logger.error("Failed to generate harnesses")
                continue
            
            # 3. Fuzz each harness
            logger.info("Step 3: Fuzzing...")
            
            for binary in binaries:
                logger.info(f"\nFuzzing: {binary}")
                
                fuzz_target(
                    target_binary=binary,
                    seed_dir=args.seeds,
                    crash_dir=crash_dir,
                    timeout=args.timeout,
                    max_iterations=args.iterations,
                    max_time=args.max_time
                )
        
        logger.success("Done!")
        
    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()