# Cross-Compilation Setup for Authority

Authority can be built FOR multiple target architectures (x86_64, aarch64, riscv64) FROM any host platform (macOS, Linux).

## Quick Start

### Verify Your Setup

```bash
./tools/verify-cross-compile.sh [ARCH]
```

Examples:
```bash
./tools/verify-cross-compile.sh x86_64    # Check x86_64 toolchain
./tools/verify-cross-compile.sh aarch64   # Check aarch64 toolchain
./tools/verify-cross-compile.sh riscv64   # Check riscv64 toolchain
```

### Building for Different Targets

```bash
# x86_64 (Intel/AMD 64-bit)
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- ARCH=x86_64 libak kernel

# aarch64 (ARM 64-bit)
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- libak kernel

# riscv64 (RISC-V 64-bit)
make PLATFORM=riscv-virt ARCH=riscv64 CROSS_COMPILE=riscv64-elf- libak kernel
```

## Installation: macOS

### Prerequisites
- Homebrew installed
- Xcode Command Line Tools

### Install Toolchains

```bash
# x86_64 target (for cross-compiling FROM ARM64 Mac)
brew install x86_64-elf-gcc

# aarch64 target (for cross-compiling FROM Intel Mac)
brew install aarch64-elf-gcc

# riscv64 target
brew install riscv64-elf-gcc
```

### Verify Installation

```bash
which x86_64-elf-gcc
which aarch64-elf-gcc
which riscv64-elf-gcc
```

## Installation: Ubuntu/Debian Linux

### Prerequisites
- GCC development tools
- Make and other build essentials

### Install Toolchains

```bash
sudo apt-get update
sudo apt-get install build-essential git

# x86_64 target (if building FROM aarch64)
sudo apt-get install gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu

# aarch64 target (if building FROM x86_64)
sudo apt-get install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu

# riscv64 target
sudo apt-get install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
```

### Verify Installation

```bash
x86_64-linux-gnu-gcc --version
aarch64-linux-gnu-gcc --version
riscv64-linux-gnu-gcc --version
```

## Installation: Fedora/RHEL

### Install Toolchains

```bash
sudo dnf install gcc gcc-c++ make

# x86_64 target
sudo dnf install gcc-x86_64-linux-gnu

# aarch64 target
sudo dnf install gcc-aarch64-linux-gnu

# riscv64 target
sudo dnf install gcc-riscv64-linux-gnu
```

## Build Matrix: What Builds Where

### Supported Combinations

| Host OS | Host Arch | Target Platform | Target Arch | Toolchain | Status |
|---------|-----------|-----------------|-------------|-----------|--------|
| macOS | x86_64 | pc | x86_64 | native clang | ✅ works |
| macOS | x86_64 | virt | aarch64 | aarch64-elf-gcc | needs install |
| macOS | x86_64 | riscv-virt | riscv64 | riscv64-elf-gcc | needs install |
| macOS | ARM64 | pc | x86_64 | x86_64-elf-gcc | ✅ installed |
| macOS | ARM64 | virt | aarch64 | native clang | ✅ works |
| macOS | ARM64 | riscv-virt | riscv64 | riscv64-elf-gcc | needs install |
| Linux | x86_64 | pc | x86_64 | native gcc | ✅ works |
| Linux | x86_64 | virt | aarch64 | aarch64-linux-gnu-gcc | ✅ standard |
| Linux | x86_64 | riscv-virt | riscv64 | riscv64-linux-gnu-gcc | ✅ standard |
| Linux | ARM64 | pc | x86_64 | x86_64-linux-gnu-gcc | ✅ standard |
| Linux | ARM64 | virt | aarch64 | native gcc | ✅ works |
| Linux | ARM64 | riscv-virt | riscv64 | riscv64-linux-gnu-gcc | ✅ standard |

### Native Builds (No Cross-Compiler Needed)

```bash
# Build for native architecture
make              # Auto-detects host architecture
make PLATFORM=pc  # x86_64
make PLATFORM=virt # aarch64
```

## Troubleshooting

### Error: "unable to create target"

```
error: unable to create target: 'No available targets are compatible with triple "riscv64-unknown-unknown-elf"'
```

**Solution**: Install the riscv64 cross-compiler toolchain

### Error: "Cross-compiler not found"

```
❌ ERROR: Cross-compiler not found: aarch64-elf-gcc
```

**Solution**: Install the appropriate toolchain using your package manager (see Installation section above)

### Error: ".section" directive issues

```
error: unexpected token in '.section' directive
```

**Cause**: Using Apple assembler for ELF assembly (on macOS)
**Solution**: Install the correct ELF cross-compiler toolchain

## Tips

### Check What You Have Installed

```bash
# macOS
brew list | grep gcc

# Linux
apt list --installed | grep gcc
```

### Verify Toolchain Works

```bash
aarch64-elf-gcc --version
aarch64-elf-gcc -dumpmachine  # Shows target triple
```

### Build All Platforms At Once

```bash
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- ARCH=x86_64 kernel && \
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel && \
make PLATFORM=riscv-virt ARCH=riscv64 CROSS_COMPILE=riscv64-elf- kernel && \
echo "All platforms built successfully"
```

## Performance Notes

- Native builds (host == target): Fastest
- Cross-compilation with compatible toolchain: Normal speed
- Missing toolchain: Build fails with clear error message

## Next Steps

After setting up cross-compilation toolchains:

1. **Run verification**: `./tools/verify-cross-compile.sh`
2. **Build for target**: `make PLATFORM=<platform> ARCH=<arch>`
3. **Test with QEMU**: Platform-specific QEMU can emulate targets
