#!/usr/bin/env python3
"""
SOFuzz - Setup Script
Install with: pip install -e .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="sofuzz",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Smart Fuzzer for Android Native Libraries (.so files)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/sofuzz",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Security Researchers",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sofuzz=sofuzz.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "sofuzz": [
            "harness/templates/*.c",
            "mutator/dictionaries/*.dict",
            "reporter/templates/*.html",
            "reporter/templates/*.css",
        ],
    },
)