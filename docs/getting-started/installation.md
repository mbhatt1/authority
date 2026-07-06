# Installation

**Install Authority and Build the Kernel**

Authority provides the cryptographic authorization, deny-by-default policy, and tamper-evident audit trail that constrain a single untrusted program running in its own VM.

## Installation Methods

```mermaid
flowchart TB
    subgraph "Option 1: authority CLI (Recommended)"
        OPS_CURL[curl authority.dev/get.sh]
        OPS_INSTALL[authority installed]
        OPS_READY[Ready to build images]

        OPS_CURL --> OPS_INSTALL --> OPS_READY
    end

    subgraph "Option 2: Build from Source"
        SRC_CLONE[git clone authority-nanos]
        SRC_DEPS[Install dependencies]
        SRC_BUILD[make kernel]
        SRC_TEST[make test]

        SRC_CLONE --> SRC_DEPS --> SRC_BUILD --> SRC_TEST
    end

    style OPS_READY fill:#27ae60,color:#fff
    style SRC_TEST fill:#27ae60,color:#fff
```

## Using authority CLI (Recommended)

The fastest way to get started with Authority is using the `authority` CLI:

```bash
curl https://authority.dev/get.sh -sSfL | sh
```

This installs both the authority CLI and the Authority kernel.

## Building from Source

### Prerequisites

#### macOS (Apple Silicon - M1/M2/M3)

```bash
brew update && brew install go wget ent qemu aarch64-elf-binutils
```

#### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install qemu-system-x86 nasm golang-go ent ruby build-essential
curl https://authority.dev/get.sh -sSfL | sh
```

### Build the Kernel

```bash
# Clone the repository
git clone https://github.com/mbhatt1/authority.git
cd authority-nanos/nanos

# Build the kernel for x86_64 (Authority kernel enabled by default)
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel

# Build the kernel for ARM64
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel
```

The Authority kernel is enabled by default via `CONFIG_AK_ENABLED=1`.

### Verify the Build

```bash
# Run tests
make test

# Run Authority kernel specific tests
cd src/agentic && make test
```

## Platform-Specific Notes

```mermaid
graph TB
    subgraph "x86_64 Platforms"
        X86_LINUX[Linux + KVM]
        X86_MAC[macOS + HVF]
        X86_CLOUD[AWS c5/c6<br/>GCE n2/c2<br/>Azure Dv3/Ev3]
    end

    subgraph "ARM64 Platforms"
        ARM_LINUX[Linux + KVM]
        ARM_MAC[macOS + HVF]
        ARM_EDGE[Raspberry Pi 4]
        ARM_CLOUD[AWS Graviton<br/>Azure Ampere]
    end

    AUTH[Authority]

    AUTH --> X86_LINUX
    AUTH --> X86_MAC
    AUTH --> X86_CLOUD
    AUTH --> ARM_LINUX
    AUTH --> ARM_MAC
    AUTH --> ARM_EDGE
    AUTH --> ARM_CLOUD

    style AUTH fill:#e74c3c,color:#fff
    style X86_CLOUD fill:#f39c12,color:#fff
    style ARM_CLOUD fill:#f39c12,color:#fff
```

### x86_64 (Intel/AMD)

- Full hardware support on Linux with KVM acceleration
- Deployed on AWS (c5/c6), GCE (n2/c2), Azure (Dv3/Ev3)
- Build with: `make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel`

### ARM64 (aarch64)

- Complete implementation with HVF acceleration on macOS
- Runs on Apple Silicon Macs (M1/M2/M3), Raspberry Pi 4, AWS Graviton, Azure Ampere
- Build with: `make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel`

::: warning macOS Intel (x86_64) Support
macOS Intel builds are no longer actively tested in CI. For x86_64 development, use Linux with KVM acceleration.
:::

## Directory Structure

After cloning, the repository structure is:

```
authority-nanos/
├── docs/                    # VitePress documentation (this site)
├── nanos/                   # Nanos kernel source
│   ├── src/
│   │   ├── agentic/        # Authority Kernel implementation
│   │   ├── x86_64/         # x86_64 platform code
│   │   ├── aarch64/        # ARM64 platform code
│   │   └── ...
│   ├── test/               # Test suites
│   └── Makefile
├── IMPLEMENTATION_SPEC.md   # Technical specification
├── SECURITY_INVARIANTS.md   # Security guarantees
└── package.json            # Documentation dependencies
```

## Next Steps

- [Quick Start](/getting-started/) - Create your first policy
- [First Program](/getting-started/first-agent) - Build and run your first program
