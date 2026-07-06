#!/usr/bin/env python3
"""
Authority Nanos Command Line Interface.

This module provides a Python CLI for Authority Nanos operations. It can be used
in multiple ways:

1. As a module: python -m authority_nanos
2. As an entry point: authority-nanos (after pip install)
3. Direct execution: python cli.py

Commands:
    run <app>        - Run an application with Authority Kernel
    build <app>      - Build an application image
    policy <file>    - Validate a policy file
    example <num>    - Run one of the bundled examples
    hello            - Run a simple hello world demo
    doctor           - Check system requirements and installation
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.BOLD = ''
        cls.NC = ''


# Check if output is a TTY
if not sys.stdout.isatty():
    Colors.disable()


def print_info(msg: str) -> None:
    """Print info message."""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def print_success(msg: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}[OK]{Colors.NC} {msg}")


def print_warning(msg: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def print_error(msg: str) -> None:
    """Print error message."""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def get_project_root() -> Path:
    """Get the project root directory."""
    # Try to find project root by looking for key files
    current = Path(__file__).resolve().parent

    # Walk up looking for indicators
    for _ in range(10):
        if (current / "Makefile").exists() and (current / "src").exists():
            return current
        if (current / "sdk" / "python").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    # Fall back to relative path from this file
    return Path(__file__).resolve().parent.parent.parent.parent


def detect_platform() -> Tuple[str, str, str]:
    """
    Detect the current platform.

    Returns:
        Tuple of (platform, machine, platform_dir)
    """
    plat = platform.system()
    machine = platform.machine().lower()

    if plat == "Darwin":
        libak_name = "libak.dylib"
        platform_dir = "pc" if machine == "x86_64" else "virt"
    else:
        libak_name = "libak.so"
        platform_dir = "pc" if machine == "x86_64" else "virt"

    return plat, machine, platform_dir


def find_libak() -> Optional[Path]:
    """Find the libak shared library."""
    plat, machine, platform_dir = detect_platform()
    libak_name = "libak.dylib" if plat == "Darwin" else "libak.so"

    project_root = get_project_root()

    # Try primary location
    libak_path = project_root / "output" / "platform" / platform_dir / "lib" / libak_name
    if libak_path.exists():
        return libak_path

    # Try alternate location
    alt_dir = "virt" if platform_dir == "pc" else "pc"
    libak_path = project_root / "output" / "platform" / alt_dir / "lib" / libak_name
    if libak_path.exists():
        return libak_path

    # Try system paths
    system_paths = [
        Path(f"/usr/local/lib/{libak_name}"),
        Path(f"/usr/lib/{libak_name}"),
        Path(f"/opt/authority/lib/{libak_name}"),
    ]
    for path in system_paths:
        if path.exists():
            return path

    return None


def find_kernel() -> Optional[Path]:
    """Find the kernel image."""
    _, _, platform_dir = detect_platform()
    project_root = get_project_root()

    # Try primary location
    kernel_path = project_root / "output" / "platform" / platform_dir / "bin" / "kernel.img"
    if kernel_path.exists():
        return kernel_path

    # Try alternate location
    alt_dir = "virt" if platform_dir == "pc" else "pc"
    kernel_path = project_root / "output" / "platform" / alt_dir / "bin" / "kernel.img"
    if kernel_path.exists():
        return kernel_path

    return None


def find_qemu() -> Optional[str]:
    """Find the QEMU binary."""
    _, machine, _ = detect_platform()

    if machine in ("x86_64", "amd64"):
        qemu_cmd = "qemu-system-x86_64"
    else:
        qemu_cmd = "qemu-system-aarch64"

    if shutil.which(qemu_cmd):
        return qemu_cmd

    return None


def setup_library_paths(libak_path: Optional[Path]) -> dict:
    """Setup library environment variables."""
    env = os.environ.copy()
    if libak_path:
        lib_dir = str(libak_path.parent)
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{env.get('LD_LIBRARY_PATH', '')}"
        env["DYLD_LIBRARY_PATH"] = f"{lib_dir}:{env.get('DYLD_LIBRARY_PATH', '')}"
        env["LIBAK_PATH"] = str(libak_path)
    return env


def get_templates_dir() -> Path:
    """Get the templates directory."""
    return Path(__file__).resolve().parent / "templates"


def get_available_templates() -> List[str]:
    """Get list of available templates."""
    templates_dir = get_templates_dir()
    if not templates_dir.exists():
        return []
    return [d.name for d in templates_dir.iterdir() if d.is_dir() and not d.name.startswith("_")]


def process_template_content(content: str, replacements: Dict[str, str]) -> str:
    """Process template content by replacing placeholders."""
    for placeholder, value in replacements.items():
        content = content.replace(f"{{{{{placeholder}}}}}", value)
    return content


def cmd_new(args: argparse.Namespace) -> int:
    """Create a new agent project from a template."""
    project_name = args.name
    template = args.template or "full"

    # Validate project name
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', project_name):
        print_error("Invalid project name. Use letters, numbers, hyphens, and underscores.")
        print_info("Project name must start with a letter.")
        return 1

    # Check if directory already exists
    project_dir = Path.cwd() / project_name
    if project_dir.exists():
        print_error(f"Directory already exists: {project_dir}")
        return 1

    # Get templates directory
    templates_dir = get_templates_dir()
    template_dir = templates_dir / template

    if not template_dir.exists():
        available = get_available_templates()
        print_error(f"Template '{template}' not found.")
        if available:
            print_info(f"Available templates: {', '.join(available)}")
        return 1

    print_info(f"Creating new project: {project_name}")
    print_info(f"Template: {template}")
    print()

    # Prepare replacements
    replacements = {
        "PROJECT_NAME": project_name,
        "DATE": datetime.now().strftime("%Y-%m-%d"),
        "YEAR": datetime.now().strftime("%Y"),
    }

    # Create project directory
    try:
        project_dir.mkdir(parents=True)
    except OSError as e:
        print_error(f"Failed to create directory: {e}")
        return 1

    # Copy and process template files
    files_created = []
    for src_path in template_dir.rglob("*"):
        if src_path.is_file():
            # Calculate relative path
            rel_path = src_path.relative_to(template_dir)
            dst_path = project_dir / rel_path

            # Create parent directories if needed
            dst_path.parent.mkdir(parents=True, exist_ok=True)

            # Process file content
            try:
                # Try to read as text and process
                content = src_path.read_text(encoding="utf-8")
                processed = process_template_content(content, replacements)
                dst_path.write_text(processed, encoding="utf-8")
            except UnicodeDecodeError:
                # Binary file - copy as-is
                shutil.copy2(src_path, dst_path)

            files_created.append(rel_path)
            print(f"  Created: {rel_path}")

    print()
    print_success(f"Project created: {project_dir}")
    print()
    print("Next steps:")
    print(f"  cd {project_name}")
    print("  pip install -r requirements.txt")
    print("  python agent.py")
    print()

    # Template-specific instructions
    if template == "langchain":
        print("For LangChain template:")
        print("  export OPENAI_API_KEY='your-key-here'")
        print()
    elif template == "crewai":
        print("For CrewAI template:")
        print("  export OPENAI_API_KEY='your-key-here'")
        print()
    elif template == "full":
        print("For full template:")
        print("  Edit config.json to customize settings")
        print("  Run tests: pytest tests/")
        print()

    print("Documentation: https://mbhatt1.github.io/authority")

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run an application with Authority Kernel."""
    app = Path(args.app)

    if not app.exists():
        print_error(f"Application not found: {app}")
        return 1

    kernel = find_kernel()
    if not kernel:
        print_error("Kernel image not found. Build with: make -j$(nproc)")
        return 1

    qemu = find_qemu()
    if not qemu:
        print_error("QEMU not found. Install qemu-system-x86_64 or qemu-system-aarch64")
        return 1

    print_info(f"Kernel: {kernel}")
    print_info(f"QEMU: {qemu}")
    print_info(f"Application: {app}")
    print()

    # Build QEMU command
    plat, machine, _ = detect_platform()

    if "x86_64" in qemu:
        cmd = [
            qemu, "-kernel", str(kernel),
            "-append", f"authority.app={app}",
            "-m", "512M",
            "-nographic",
            "-no-reboot"
        ]
    else:
        cmd = [
            qemu, "-M", "virt", "-cpu", "cortex-a57",
            "-kernel", str(kernel),
            "-append", f"authority.app={app}",
            "-m", "512M",
            "-nographic",
            "-no-reboot"
        ]

    try:
        result = subprocess.run(cmd)
        return result.returncode
    except KeyboardInterrupt:
        return 130


def cmd_build(args: argparse.Namespace) -> int:
    """Build an application image."""
    app = Path(args.app)
    output = args.output or "image.img"

    if not app.exists():
        print_error(f"Application not found: {app}")
        return 1

    kernel = find_kernel()
    if not kernel:
        print_error("Kernel image not found. Build with: make -j$(nproc)")
        return 1

    print_info(f"Building image for: {app}")
    print_info(f"Output: {output}")

    # Try to find ops tool
    project_root = get_project_root()
    ops_path = project_root / "tools" / "ops" / "ops"

    if not ops_path.exists():
        ops_path = shutil.which("ops")

    if ops_path:
        cmd = [str(ops_path), "build", str(app), "-k", str(kernel), "-o", output]
        try:
            result = subprocess.run(cmd)
            if result.returncode == 0:
                print_success(f"Built image: {output}")
            return result.returncode
        except Exception as e:
            print_error(f"Build failed: {e}")
            return 1
    else:
        print_error("ops tool not found. Install ops or build from tools/ops/")
        return 1


def cmd_policy(args: argparse.Namespace) -> int:
    """Handle policy subcommands."""
    # This is now a parent command - dispatch to subcommand
    if hasattr(args, 'policy_func'):
        return args.policy_func(args)

    # Legacy behavior: if 'file' is provided directly, validate it
    if hasattr(args, 'file') and args.file:
        args.policy_file = args.file
        return cmd_policy_validate(args)

    print_error("Usage: authority-nanos policy <subcommand>")
    print()
    print("Subcommands:")
    print("  wizard           Interactive policy generator")
    print("  validate <file>  Validate a policy file")
    print("  explain <file>   Explain what a policy allows/denies")
    print("  merge <f1> <f2>  Merge two policies")
    return 1


def cmd_policy_wizard(args: argparse.Namespace) -> int:
    """Run the interactive policy wizard."""
    from .policy import PolicyWizard

    wizard = PolicyWizard()

    try:
        policy = wizard.run()
    except (KeyboardInterrupt, EOFError):
        print()
        print_info("Wizard cancelled.")
        return 1

    # Save the policy
    output = getattr(args, 'output', None) or "policy.json"
    wizard.save(policy, output)

    print()
    print_success(f"Generated policy saved to: {output}")

    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Validate a policy file."""
    from .policy import PolicyValidator, ValidationSeverity

    policy_file = Path(args.policy_file)

    if not policy_file.exists():
        print_error(f"Policy file not found: {policy_file}")
        return 1

    print_info(f"Validating policy: {policy_file}")
    print()

    validator = PolicyValidator()
    result = validator.validate_file(policy_file)

    # Print all messages
    for msg in result.messages:
        if msg.severity == ValidationSeverity.ERROR:
            print_error(f"{msg.path}: {msg.message}" if msg.path else msg.message)
        elif msg.severity == ValidationSeverity.WARNING:
            print_warning(f"{msg.path}: {msg.message}" if msg.path else msg.message)
        else:
            print_info(f"{msg.path}: {msg.message}" if msg.path else msg.message)

        if msg.suggestion:
            print(f"        Suggestion: {msg.suggestion}")

    print()

    if result.valid:
        print_success("Policy validation: PASSED")
        if result.warnings:
            print(f"  ({len(result.warnings)} warning(s))")
        return 0
    else:
        print_error(f"Policy validation: FAILED ({len(result.errors)} error(s))")
        return 1


def cmd_policy_explain(args: argparse.Namespace) -> int:
    """Explain what a policy allows and denies."""
    from .policy import PolicyExplainer

    policy_file = Path(args.policy_file)

    if not policy_file.exists():
        print_error(f"Policy file not found: {policy_file}")
        return 1

    explainer = PolicyExplainer()
    explanation = explainer.explain_file(policy_file)

    print(explanation)

    return 0


def cmd_policy_merge(args: argparse.Namespace) -> int:
    """Merge two or more policy files."""
    from .policy import PolicyMerger, MergeMode

    paths = [Path(args.file1), Path(args.file2)]

    # Add any additional files
    if hasattr(args, 'additional_files') and args.additional_files:
        paths.extend([Path(f) for f in args.additional_files])

    # Check all files exist
    for path in paths:
        if not path.exists():
            print_error(f"Policy file not found: {path}")
            return 1

    # Determine merge mode
    mode = MergeMode.INTERSECTION if getattr(args, 'intersection', False) else MergeMode.UNION

    print_info(f"Merging {len(paths)} policies (mode: {mode.value})")

    merger = PolicyMerger()
    merged, conflicts = merger.merge_files(paths, mode)

    if conflicts:
        print()
        print_warning("Merge conflicts/notes:")
        for conflict in conflicts:
            print(f"  - {conflict}")

    # Determine output
    output = getattr(args, 'output', None) or "merged_policy.json"

    # Save merged policy
    with open(output, "w") as f:
        json.dump(merged, f, indent=2)

    print()
    print_success(f"Merged policy saved to: {output}")

    return 0


def cmd_example(args: argparse.Namespace) -> int:
    """Run one of the bundled examples."""
    num = args.num
    project_root = get_project_root()
    examples_dir = project_root / "examples"

    if num is None:
        # List available examples
        print_error("Usage: authority-nanos example <number>")
        print()
        print("Available examples:")
        for f in sorted(examples_dir.glob("[0-9][0-9]_*.py")):
            name = f.stem
            # Parse name like "01_heap_operations" -> "1 heap operations"
            parts = name.split("_", 1)
            if len(parts) == 2:
                num_part = parts[0].lstrip("0") or "0"
                desc = parts[1].replace("_", " ")
                print(f"  {num_part}) {desc}")
        return 1

    # Find example file
    example_num = f"{int(num):02d}"
    example_files = list(examples_dir.glob(f"{example_num}_*.py"))

    if not example_files:
        print_error(f"Example {num} not found")
        return 1

    example_file = example_files[0]

    # Setup environment
    libak = find_libak()
    if libak:
        env = setup_library_paths(libak)
        print_info(f"Using libak: {libak}")
    else:
        env = os.environ.copy()
        print_warning("libak not found - example may fail")
        print_info("Build with: make -j$(nproc)")

    # Add SDK to Python path
    sdk_path = project_root / "sdk" / "python"
    env["PYTHONPATH"] = f"{sdk_path}:{env.get('PYTHONPATH', '')}"

    print_info(f"Running: {example_file.name}")
    print()

    # Run example
    try:
        result = subprocess.run([sys.executable, str(example_file)], env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130


def cmd_hello(args: argparse.Namespace) -> int:
    """Run a simple hello world demo."""
    return hello()


def hello() -> int:
    """
    Run a self-contained hello world demo in simulation mode.

    This function can be called directly as an entry point or
    via the 'hello' command. It demonstrates basic Authority Nanos
    concepts without requiring the actual kernel.

    Returns:
        Exit code (0 for success)
    """
    print_info("Authority Nanos Hello World Demo")
    print()

    print("=" * 60)
    print("  Authority Nanos - Hello World Demo")
    print("  Running in SIMULATION MODE (no kernel required)")
    print("=" * 60)
    print()

    # Simulated typed heap
    class SimulatedHeap:
        """Simple simulation of Authority Kernel's typed heap."""

        def __init__(self):
            self._objects = {}
            self._next_id = 1

        def alloc(self, type_name: str, initial_value: bytes) -> dict:
            """Allocate an object in the simulated heap."""
            obj_id = self._next_id
            self._next_id += 1
            self._objects[obj_id] = {
                'type': type_name,
                'value': initial_value,
                'version': 1,
                'created': datetime.now().isoformat()
            }
            return {'id': obj_id, 'version': 1}

        def read(self, handle: dict) -> bytes:
            """Read an object from the simulated heap."""
            obj_id = handle['id']
            if obj_id not in self._objects:
                raise KeyError(f"Object {obj_id} not found")
            return self._objects[obj_id]['value']

        def write(self, handle: dict, patch: bytes) -> int:
            """Update an object using JSON Patch."""
            obj_id = handle['id']
            if obj_id not in self._objects:
                raise KeyError(f"Object {obj_id} not found")

            obj = self._objects[obj_id]
            current = json.loads(obj['value'].decode('utf-8'))

            # Apply JSON patch (simplified)
            for op in json.loads(patch.decode('utf-8')):
                if op['op'] == 'replace':
                    path = op['path'].lstrip('/').split('/')
                    target = current
                    for key in path[:-1]:
                        if key.isdigit():
                            target = target[int(key)]
                        else:
                            target = target[key]
                    last_key = path[-1]
                    if last_key.isdigit():
                        target[int(last_key)] = op['value']
                    else:
                        target[last_key] = op['value']
                elif op['op'] == 'add':
                    path = op['path'].lstrip('/').split('/')
                    target = current
                    for key in path[:-1]:
                        if key.isdigit():
                            target = target[int(key)]
                        else:
                            target = target[key]
                    last_key = path[-1]
                    if last_key.isdigit():
                        target.insert(int(last_key), op['value'])
                    else:
                        target[last_key] = op['value']

            obj['value'] = json.dumps(current).encode('utf-8')
            obj['version'] += 1
            return obj['version']

        def delete(self, handle: dict) -> None:
            """Delete an object from the simulated heap."""
            obj_id = handle['id']
            if obj_id in self._objects:
                del self._objects[obj_id]

    # Run demo
    heap = SimulatedHeap()

    print("[1] Allocating a counter object...")
    counter_data = json.dumps({"value": 0, "name": "hello-counter"}).encode()
    handle = heap.alloc("counter", counter_data)
    print(f"    Allocated: Handle(id={handle['id']}, version={handle['version']})")

    print()
    print("[2] Reading the object...")
    data = heap.read(handle)
    counter = json.loads(data.decode('utf-8'))
    print(f"    Read: {counter}")

    print()
    print("[3] Updating value using JSON Patch...")
    patch = json.dumps([{"op": "replace", "path": "/value", "value": 42}]).encode()
    new_version = heap.write(handle, patch)
    print(f"    Updated to version: {new_version}")

    print()
    print("[4] Reading updated value...")
    updated_data = heap.read(handle)
    updated_counter = json.loads(updated_data.decode('utf-8'))
    print(f"    Updated: {updated_counter}")

    print()
    print("[5] Deleting object...")
    heap.delete(handle)
    print(f"    Deleted handle {handle['id']}")

    print()
    print("=" * 60)
    print("  Demo completed successfully!")
    print()
    print("  Next steps:")
    print("    - Build the kernel:  make -j$(nproc)")
    print("    - Run real examples: authority-nanos example 1")
    print("    - Check status:      authority-nanos doctor")
    print("=" * 60)

    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check system requirements and installation."""
    print_info("Authority Nanos System Check")
    print()

    plat, machine, platform_dir = detect_platform()

    print("System Information:")
    print(f"  Platform: {plat}")
    print(f"  Architecture: {machine}")
    print()

    # Check Python
    print("Python:")
    print_success(f"  python3: Python {platform.python_version()}")

    # Check QEMU
    print()
    print("QEMU:")
    qemu_x86 = shutil.which("qemu-system-x86_64")
    if qemu_x86:
        try:
            result = subprocess.run([qemu_x86, "--version"], capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            print_success(f"  qemu-system-x86_64: {version}")
        except Exception:
            print_success(f"  qemu-system-x86_64: Found")
    else:
        print_warning("  qemu-system-x86_64: Not found")

    qemu_arm = shutil.which("qemu-system-aarch64")
    if qemu_arm:
        try:
            result = subprocess.run([qemu_arm, "--version"], capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            print_success(f"  qemu-system-aarch64: {version}")
        except Exception:
            print_success(f"  qemu-system-aarch64: Found")
    else:
        print_warning("  qemu-system-aarch64: Not found")

    # Check kernel
    print()
    print("Authority Kernel:")
    kernel = find_kernel()
    if kernel:
        print_success(f"  kernel.img: {kernel}")
    else:
        print_warning("  kernel.img: Not found (build with: make -j$(nproc))")

    # Check libak
    print()
    print("libak Library:")
    libak = find_libak()
    libak_name = "libak.dylib" if plat == "Darwin" else "libak.so"
    if libak:
        print_success(f"  {libak_name}: {libak}")
    else:
        print_warning(f"  {libak_name}: Not found (build with: make -j$(nproc))")

    # Check Python SDK
    print()
    print("Python SDK:")
    project_root = get_project_root()
    sdk_path = project_root / "sdk" / "python" / "authority_nanos"
    if sdk_path.exists():
        print_success(f"  SDK path: {sdk_path}")
    else:
        print_warning(f"  SDK not found at {sdk_path}")

    # Check examples
    print()
    print("Examples:")
    examples_dir = project_root / "examples"
    example_count = len(list(examples_dir.glob("[0-9][0-9]_*.py")))
    if example_count > 0:
        print_success(f"  {example_count} example(s) available")
    else:
        print_warning("  No examples found")

    # Check build tools
    print()
    print("Build Tools:")
    make = shutil.which("make")
    if make:
        try:
            result = subprocess.run([make, "--version"], capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            print_success(f"  make: {version}")
        except Exception:
            print_success("  make: Found")
    else:
        print_error("  make: Not found")

    gcc = shutil.which("gcc")
    if gcc:
        try:
            result = subprocess.run([gcc, "--version"], capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            print_success(f"  gcc: {version}")
        except Exception:
            print_success("  gcc: Found")
    else:
        print_warning("  gcc: Not found")

    clang = shutil.which("clang")
    if clang:
        try:
            result = subprocess.run([clang, "--version"], capture_output=True, text=True)
            version = result.stdout.split('\n')[0]
            print_success(f"  clang: {version}")
        except Exception:
            print_success("  clang: Found")
    else:
        print_warning("  clang: Not found")

    # Summary
    print()
    print("---")
    if kernel and libak:
        print_success("Authority Nanos is ready to use!")
        print()
        print("Quick start:")
        print("  authority-nanos hello     - Run hello world demo")
        print("  authority-nanos example 1 - Run first example")
    else:
        print_warning("Authority Nanos needs to be built")
        print()
        print("Build instructions:")
        print(f"  cd {project_root}")
        print("  make -j$(nproc)")

    return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Show version information."""
    print("Authority Nanos CLI v0.1.0")
    print()
    print(f"Project: {get_project_root()}")
    print(f"Python: {platform.python_version()}")

    # Try to get git info
    project_root = get_project_root()
    if (project_root / ".git").exists():
        try:
            commit = subprocess.run(
                ["git", "-C", str(project_root), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True
            ).stdout.strip()
            branch = subprocess.run(
                ["git", "-C", str(project_root), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True
            ).stdout.strip()
            print(f"Git: {branch} @ {commit}")
        except Exception:
            pass

    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="authority-nanos",
        description="Authority Nanos Command Line Interface",
        epilog="For more information, see: https://mbhatt1.github.io/authority"
    )

    parser.add_argument(
        "--version", "-V",
        action="store_true",
        help="Show version information"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # new command - create new project from template
    new_parser = subparsers.add_parser(
        "new",
        help="Create a new agent project from a template"
    )
    new_parser.add_argument(
        "name",
        help="Name of the new project"
    )
    new_parser.add_argument(
        "-t", "--template",
        choices=["minimal", "langchain", "crewai", "full"],
        default="full",
        help="Template to use (default: full)"
    )
    new_parser.set_defaults(func=cmd_new)

    # run command
    run_parser = subparsers.add_parser("run", help="Run an application with Authority Kernel")
    run_parser.add_argument("app", help="Path to the application")
    run_parser.set_defaults(func=cmd_run)

    # build command
    build_parser = subparsers.add_parser("build", help="Build an application image")
    build_parser.add_argument("app", help="Path to the application")
    build_parser.add_argument("-o", "--output", help="Output image file (default: image.img)")
    build_parser.set_defaults(func=cmd_build)

    # policy command with subcommands
    policy_parser = subparsers.add_parser(
        "policy",
        help="Policy management commands"
    )
    policy_parser.set_defaults(func=cmd_policy)

    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command",
        help="Policy subcommands"
    )

    # policy wizard
    policy_wizard_parser = policy_subparsers.add_parser(
        "wizard",
        help="Interactive policy generator"
    )
    policy_wizard_parser.add_argument(
        "-o", "--output",
        default="policy.json",
        help="Output file (default: policy.json)"
    )
    policy_wizard_parser.set_defaults(policy_func=cmd_policy_wizard)

    # policy validate
    policy_validate_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate a policy file"
    )
    policy_validate_parser.add_argument(
        "policy_file",
        help="Policy file to validate (JSON or TOML)"
    )
    policy_validate_parser.set_defaults(policy_func=cmd_policy_validate)

    # policy explain
    policy_explain_parser = policy_subparsers.add_parser(
        "explain",
        help="Explain what a policy allows/denies"
    )
    policy_explain_parser.add_argument(
        "policy_file",
        help="Policy file to explain"
    )
    policy_explain_parser.set_defaults(policy_func=cmd_policy_explain)

    # policy merge
    policy_merge_parser = policy_subparsers.add_parser(
        "merge",
        help="Merge two or more policies"
    )
    policy_merge_parser.add_argument(
        "file1",
        help="First policy file"
    )
    policy_merge_parser.add_argument(
        "file2",
        help="Second policy file"
    )
    policy_merge_parser.add_argument(
        "additional_files",
        nargs="*",
        help="Additional policy files to merge"
    )
    policy_merge_parser.add_argument(
        "-o", "--output",
        default="merged_policy.json",
        help="Output file (default: merged_policy.json)"
    )
    policy_merge_parser.add_argument(
        "-i", "--intersection",
        action="store_true",
        help="Use intersection mode (most restrictive)"
    )
    policy_merge_parser.set_defaults(policy_func=cmd_policy_merge)

    # Legacy: support 'policy <file>' for backwards compatibility
    policy_parser.add_argument(
        "file",
        nargs="?",
        help="Policy file (for backwards compatibility with 'policy <file>')"
    )

    # example command
    example_parser = subparsers.add_parser("example", help="Run one of the bundled examples")
    example_parser.add_argument("num", nargs="?", type=int, help="Example number")
    example_parser.set_defaults(func=cmd_example)

    # hello command
    hello_parser = subparsers.add_parser("hello", help="Run a simple hello world demo")
    hello_parser.set_defaults(func=cmd_hello)

    # doctor command
    doctor_parser = subparsers.add_parser("doctor", help="Check system requirements")
    doctor_parser.set_defaults(func=cmd_doctor)

    # version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        argv: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    if args.command is None:
        parser.print_help()
        return 0

    if hasattr(args, 'func'):
        return args.func(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
