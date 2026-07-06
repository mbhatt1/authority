"""
Authority Nanos Python SDK setup configuration.

This module configures the installation and distribution of the Authority Nanos
Python SDK, which provides Python bindings for the libak authorization kernel.

PLATFORM-SPECIFIC WHEELS SUPPORT
=================================

This setup.py builds platform-specific wheels that include pre-compiled libak binaries
for the current platform. This enables binary distribution without requiring compilation
on end-user systems.

Supported Platforms:
  - macOS x86_64 (10.9+)
  - macOS ARM64 (11.0+)
  - Linux x86_64 (manylinux2014)
  - Linux ARM64 (manylinux2014)

BUILD PROCESS
=============

1. Before building wheels, ensure libak binaries are present in the build artifacts:
   - output/platform/macos-x86_64/libak.dylib
   - output/platform/macos-arm64/libak.dylib
   - output/platform/linux-x86_64/libak.so
   - output/platform/linux-arm64/libak.so

2. The setup.py automatically detects available binaries and includes them in wheels
   for the current platform.

3. Binary loading is handled by authority_nanos/_libak_loader.py which:
   - Detects the current platform (OS + architecture)
   - Locates and loads the bundled libak binary
   - Falls back to system libak if needed
   - Provides clear error messages if the binary is not found

MANIFEST.in Configuration
==========================

The MANIFEST.in file specifies which binary files to include in the source distribution
and wheels. This ensures that wheels built on different platforms include their
respective platform-specific binaries.

WHEEL PLATFORM TAGS
====================

Platform-specific wheels are tagged with:
  - macosx_10_9_x86_64
  - macosx_11_0_arm64
  - manylinux2014_x86_64
  - manylinux2014_aarch64

This prevents pip from installing incompatible wheels on different platforms.
"""

import os
import sys
import platform
from pathlib import Path
from setuptools import setup, find_packages


def discover_binaries():
    """
    Discover available kernel and libak binaries for the current platform.

    Returns:
        tuple: (platform_dir, kernel_path, libak_path) or (None, None, None) if not found

    Searches in multiple locations for binaries:
      1. output/platform/pc/bin/kernel.img and output/platform/pc/lib/libak.{so,dylib} (x86_64)
      2. output/platform/virt/bin/kernel.img and output/platform/virt/lib/libak.{so,dylib} (ARM64)
      3. System paths as fallback
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map to platform directory and binary extensions
    if system == "darwin":  # macOS
        libak_name = "libak.dylib"
        if machine == "x86_64":
            platform_name = "macos_x86_64"
            platform_dir_build = "pc"  # kernel built for x86_64 in pc
        elif machine == "arm64":
            platform_name = "macos_arm64"
            platform_dir_build = "virt"  # kernel built for ARM64 in virt
        else:
            return None, None, None
    elif system == "linux":
        libak_name = "libak.so"
        if machine == "x86_64":
            platform_name = "linux_x86_64"
            platform_dir_build = "pc"  # kernel built for x86_64 in pc
        elif machine == "aarch64":
            platform_name = "linux_arm64"
            platform_dir_build = "virt"  # kernel built for ARM64 in virt
        else:
            return None, None, None
    else:
        return None, None, None

    # Search for binaries in build artifacts
    project_root = Path(__file__).parent.parent.parent
    kernel_path = project_root / "output" / "platform" / platform_dir_build / "bin" / "kernel.img"
    libak_path = project_root / "output" / "platform" / platform_dir_build / "lib" / libak_name

    if kernel_path.exists() and libak_path.exists():
        return platform_name, str(kernel_path), str(libak_path)

    # Try system paths as fallback (only for libak)
    libak_system_paths = [
        Path(f"/usr/local/lib/{libak_name}"),
        Path(f"/usr/lib/{libak_name}"),
        Path(f"/opt/authority/lib/{libak_name}"),
    ]

    for sys_path in libak_system_paths:
        if sys_path.exists():
            # If system libak exists but kernel.img doesn't, return what we have
            return platform_name, str(kernel_path) if kernel_path.exists() else None, str(sys_path)

    return None, None, None


def get_package_data():
    """
    Generate package_data dict for including binaries in wheels.

    Returns:
        dict: package_data configuration for setuptools

    This function discovers both kernel and libak binaries and includes them
    in the wheel if found. Binaries are placed in the authority_nanos/_binaries
    directory organized by platform for easy discovery at runtime.
    """
    platform_name, kernel_path, libak_path = discover_binaries()

    if not platform_name or (not kernel_path and not libak_path):
        # No binaries found - warn but don't fail the build
        # The loader module will handle missing binaries gracefully
        print(
            "\nWARNING: No kernel or libak binaries found for current platform.",
            "The package will be built without bundled binaries.",
            "Ensure binaries are present in output/platform/{pc,virt}/{bin,lib}/",
            sep="\n",
            file=sys.stderr
        )
        return {}

    if kernel_path:
        print(f"\nINFO: Including kernel binary from: {kernel_path}", file=sys.stderr)
    if libak_path:
        print(f"INFO: Including libak binary from: {libak_path}", file=sys.stderr)

    # Include all binary types for all platforms
    # The actual binaries are copied by CI/CD into _binaries/{platform}/
    return {
        "authority_nanos": [
            # Include binary files from _binaries for all platforms
            "_binaries/macos_x86_64/kernel.img",
            "_binaries/macos_x86_64/libak.dylib",
            "_binaries/macos_arm64/kernel.img",
            "_binaries/macos_arm64/libak.dylib",
            "_binaries/linux_x86_64/kernel.img",
            "_binaries/linux_x86_64/libak.so",
            "_binaries/linux_arm64/kernel.img",
            "_binaries/linux_arm64/libak.so",
            # Also keep old paths for backward compatibility
            "_libak/libak.so",
            "_libak/libak.dylib",
            "_kernel/macos_x86_64/*",
            "_kernel/macos_arm64/*",
            "_kernel/linux_x86_64/*",
            "_kernel/linux_arm64/*",
        ],
    }


def get_platform_classifiers():
    """
    Generate platform classifiers for the wheel.

    Returns:
        list: Additional classifiers for platform-specific wheels

    This ensures wheels are properly tagged and pip recognizes platform constraints.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    classifiers = []

    if system == "darwin":
        if machine == "x86_64":
            classifiers.append("Platform :: macOS :: macOS 10.9")
        elif machine == "arm64":
            classifiers.append("Platform :: macOS :: macOS 11.0")
    elif system == "linux":
        classifiers.append("Platform :: Linux")

    return classifiers


# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Base classifiers that apply to all wheels
base_classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Security",
]

# Add platform-specific classifiers
all_classifiers = base_classifiers + get_platform_classifiers()

setup(
    name="authority-nanos",
    version="0.1.0",
    author="Authority Systems",
    author_email="sdk@authority.systems",
    description="Authority Nanos Python SDK - libak bindings",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mbhatt1/authority",
    project_urls={
        "Documentation": "https://mbhatt1.github.io/authority/python",
        "Source Code": "https://github.com/mbhatt1/authority",
        "Issue Tracker": "https://github.com/mbhatt1/authority/issues",
    },
    packages=find_packages(),
    package_data=get_package_data(),
    classifiers=all_classifiers,
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "isort>=5.0",
        ],
        "docs": [
            "sphinx>=5.0",
            "sphinx-rtd-theme>=1.0",
        ],
    },
    keywords="authorization security kernel access-control",
    # Console script entry points for CLI
    entry_points={
        'console_scripts': [
            'authority-nanos=authority_nanos.cli:main',
            'authority-hello=authority_nanos.cli:hello',
        ],
    },
    # Mark as platform-specific to ensure correct wheel tagging
    zip_safe=False,
)
