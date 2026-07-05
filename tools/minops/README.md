# minops - Minimal Nanos ops Replacement

A lightweight Go tool that replaces the external `ops` tool for running kernel examples without external dependencies.

## Features

- ✅ Runs Python applications inside Authority unikernel
- ✅ No external dependencies (ops tool not required)
- ✅ Integrated image creation using mkfs
- ✅ QEMU auto-detection and launch
- ✅ Cross-platform support (macOS, Linux)

## Building

```bash
cd tools/minops
go build -o minops main.go
```

Binary will be created as `./minops`

## Usage

### Run a Python application inside the kernel

```bash
minops run main.py -c config.json -m 256 -v
```

Options:
- `main.py` - Python application to run
- `-c config.json` - Configuration file (optional, default: config.json)
- `-m 256` - Memory in MB (optional, default: 512)
- `-v` - Verbose output (optional)

### Create a bootable image without launching kernel

```bash
minops mkimage main.py output.img -c config.json -v
```

This creates a bootable QEMU image that can be launched manually:

```bash
qemu-system-x86_64 -m 256 -display none -serial stdio -hda output.img
```

## Configuration File (config.json)

Example:

```json
{
  "Args": ["main.py"],
  "ManifestPassthrough": {
    "expected_exit_code": ["0"],
    "debug_exit": "t"
  }
}
```

Supported fields:
- `Args` - Command-line arguments to pass to the program
- `Env` - Environment variables (optional)
- `ManifestPassthrough` - Additional manifest settings for the kernel

## Requirements

- Authority kernel built: `output/platform/pc/bin/kernel.img`
- mkfs tool built: `output/tools/bin/mkfs`
- QEMU: `qemu-system-x86_64` (for running kernel examples)
- Go 1.18+ (for building minops)

## How It Works

1. **Image Creation**: minops uses the kernel's mkfs tool to create a bootable filesystem image with:
   - The embedded kernel
   - The Python application
   - Configuration from config.json

2. **Manifest Generation**: minops generates a Nanos tuple-format manifest that describes:
   - Files to include (main.py)
   - Program to run (python3)
   - Arguments and environment variables
   - Kernel configuration options

3. **QEMU Launch**: minops launches QEMU with the created image as a virtual disk

## Example

Running hello-auth kernel example:

```bash
cd kernel-examples/hello-auth
/Users/mbhatt/authority/nanos/tools/minops/minops run main.py -c config.json -m 256 -v
```

Expected output:
- Kernel boots
- Python runs main.py
- Results displayed on console
- Kernel shuts down

## Troubleshooting

**Error: "Cannot find kernel image"**
- Ensure kernel is built: `make -j$(nproc)`
- Check: `ls output/platform/pc/bin/kernel.img`

**Error: "mkfs tool not found"**
- Ensure mkfs is built: `make -j$(nproc)`
- Check: `ls output/tools/bin/mkfs`

**Error: "qemu-system-x86_64 not found"**
- Install QEMU: `brew install qemu` (macOS) or `apt install qemu-system-x86` (Linux)

**Manifest parse error**
- Check that config.json is valid JSON
- Ensure main.py file exists and is readable

## Implementation Details

- Written in Go for cross-platform compatibility
- No external dependencies beyond Go standard library
- Creates images using the same mkfs tool as the build system
- Manifest format: Nanos tuple format (not JSON)
- Image format: Bootable QEMU disk image with embedded kernel
