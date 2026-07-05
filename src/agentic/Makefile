# Authority Kernel - Build Configuration
#
# SPDX-License-Identifier: Apache-2.0
#
# This Makefile builds:
# 1. The Authority Kernel module for Nanos (included in kernel.elf)
# 2. libak - Shared library for Python SDK and C applications

include ../../vars.mk

# ============================================================================
# PART 1: Kernel Module Object Files (for inclusion in kernel.elf)
# ============================================================================

# Module name
AK_MODULE := agentic

# Kernel source files (compiled into kernel.elf)
#
# NOTE: The AUTHORITATIVE kernel source lists are SRCS-agentic in
# platform/pc/Makefile, platform/virt/Makefile and
# platform/riscv-virt/Makefile. This list mirrors that core set and
# must be kept in sync with them.
#
# NOT in the kernel build (future work): ak_agentic.c, ak_context.c,
# ak_effects.c, ak_posix_route.c, ak_policy_v2.c, ak_tool_registry.c,
# ak_observe.c, ak_process.c, ak_state_mgmt.c, ak_stream.c,
# ak_agent_ipc.c, ak_deny_ux.c, ak_fd_table.c, ak_policy_toml.c,
# ak_record.c (duplicate symbols and unverified dependencies; see the
# platform Makefiles for details).
AK_SRCS := \
	ak_approval.c \
	ak_audit.c \
	ak_budget.c \
	ak_capability.c \
	ak_ed25519.c \
	ak_heap.c \
	ak_inference.c \
	ak_ipc.c \
	ak_lz4.c \
	ak_nanos.c \
	ak_net_enforce.c \
	ak_pattern.c \
	ak_policy.c \
	ak_sanitize.c \
	ak_secrets.c \
	ak_state.c \
	ak_syscall.c \
	ak_virtio_proxy.c \
	ak_wasm.c \
	ak_wasm_host.c

# Headers
AK_HDRS := \
	ak_types.h \
	ak_approval.h \
	ak_assert.h \
	ak_audit.h \
	ak_budget.h \
	ak_capability.h \
	ak_compat.h \
	ak_config.h \
	ak_ed25519.h \
	ak_heap.h \
	ak_inference.h \
	ak_ipc.h \
	ak_net_enforce.h \
	ak_pattern.h \
	ak_policy.h \
	ak_sanitize.h \
	ak_secrets.h \
	ak_state.h \
	ak_syscall.h \
	ak_virtio_proxy.h \
	ak_wasm.h

# Object files
AK_OBJS := $(AK_SRCS:.c=.o)

# Compiler flags
AK_CFLAGS := \
	-I$(SRCDIR)/agentic \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/kernel \
	-DAK_DEBUG=$(DEBUG) \
	-DCONFIG_AK_ENABLED=1

# Security flags
AK_CFLAGS += \
	-fstack-protector-strong \
	-fno-strict-aliasing

# Optimization
ifeq ($(DEBUG),1)
AK_CFLAGS += -O0 -g -DAK_DEBUG=1
else
AK_CFLAGS += -O2 -DNDEBUG
endif

# ============================================================================
# PART 2: libak Shared Library
# ============================================================================

# libak sources
LIBAK_SRCS = libak.c

# Convert to object files
LIBAK_OBJS = $(LIBAK_SRCS:.c=.libak.o)

# Output directory
LIBAK_LIBDIR = $(PLATFORMOBJDIR)/lib

# Library filename based on platform
ifeq ($(UNAME_s),Darwin)
LIBAK_LIB = $(LIBAK_LIBDIR)/libak.dylib
LIBAK_LDFLAGS = -dynamiclib
else
LIBAK_LIB = $(LIBAK_LIBDIR)/libak.so
LIBAK_LDFLAGS = -shared -fPIC
endif

# Compiler flags for libak (different from kernel module)
LIBAK_CFLAGS = \
	-fPIC \
	-O2 \
	-Wall \
	-Wextra \
	-fstack-protector-strong \
	-fno-strict-aliasing \
	-I. \
	-I$(SRCDIR) \
	-I$(PLATFORMDIR) \
	-DCONFIG_AK_ENABLED \
	-DCONFIG_SYSCALL_AGENTIC=1

# ============================================================================
# Build Rules
# ============================================================================

.PHONY: all clean distclean libak

# Build libak only if source file exists
ifeq ($(wildcard libak.c),libak.c)
all: $(AK_OBJS) libak
libak: $(LIBAK_LIB)
else
all: $(AK_OBJS)
libak:
	@echo "Warning: libak.c not found, skipping libak shared library build"
endif

# Kernel module object files
%.o: %.c $(AK_HDRS)
	$(CC) $(CFLAGS) $(AK_CFLAGS) -c $< -o $@

# Create lib directory
$(LIBAK_LIBDIR):
	@mkdir -p $@

# Compile libak object files with different naming
# Use target compiler to respect cross-compilation toolchain
%.libak.o: %.c
	@echo "  CC    $< (shared library for $(ARCH))"
	$(Q)$(CC) $(LIBAK_CFLAGS) -c $< -o $@

# Link shared library using target compiler
$(LIBAK_LIB): $(LIBAK_LIBDIR) $(LIBAK_OBJS)
	@echo "  LD    $@ (for $(ARCH))"
	$(Q)$(CC) $(LIBAK_LDFLAGS) $(LIBAK_OBJS) -o $@
ifeq ($(UNAME_s),Darwin)
	@echo "  CODESIGN  $@"
	$(Q)codesign -s - $@ 2>/dev/null || true
endif
	@echo "  Built: $@"

clean:
	rm -f $(AK_OBJS)
	rm -f $(LIBAK_OBJS)
	rm -f $(LIBAK_LIB)

distclean: clean
	@rmdir $(LIBAK_LIBDIR) 2>/dev/null || true

# Dependencies for kernel module
ak_capability.o: ak_capability.c ak_capability.h ak_types.h
ak_audit.o: ak_audit.c ak_audit.h ak_types.h
ak_budget.o: ak_budget.c ak_budget.h ak_types.h ak_compat.h
ak_heap.o: ak_heap.c ak_heap.h ak_types.h ak_audit.h
ak_ipc.o: ak_ipc.c ak_ipc.h ak_types.h ak_capability.h
ak_net_enforce.o: ak_net_enforce.c ak_net_enforce.h ak_audit.h ak_budget.h ak_capability.h ak_sanitize.h
ak_policy.o: ak_policy.c ak_policy.h ak_types.h ak_capability.h
ak_syscall.o: ak_syscall.c ak_syscall.h ak_types.h ak_capability.h ak_audit.h ak_heap.h ak_policy.h ak_ipc.h ak_budget.h
ak_nanos.o: ak_nanos.c ak_syscall.h

# Integration with main kernel build:
# the kernel compiles SRCS-agentic as listed in the platform Makefiles
# (platform/{pc,virt,riscv-virt}/Makefile), NOT via this Makefile.
# Do NOT use $(wildcard $(SRCDIR)/agentic/*.c): several sources in this
# directory are intentionally excluded from the kernel build (see the
# comment above AK_SRCS).
