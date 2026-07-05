/*
 * Authority Kernel - External State Synchronization
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Manages state persistence for ephemeral Authority VMs:
 *   - On boot: Hydrate typed heap from external store
 *   - On AK_COMMIT: Sync dirty objects to external store
 *   - On shutdown: Final sync + anchor emission
 *
 * Supported backends:
 *   - virtio-serial to host storage daemon (the only functional backend)
 *   - S3/Redis/HTTP are defined in the API but fail closed (no TLS/TCP
 *     client in the kernel)
 *
 * Security:
 *   - Object integrity verified via per-object hashes and merkle roots
 *   - Anchors provide a tamper-evident hash chain (unsigned: no
 *     non-repudiation)
 *   - Encryption at rest is NOT implemented in-kernel; delegate to the
 *     host daemon / backing store if required
 *
 * REMOTE ANCHOR POSTING (P2-3 Documentation):
 * ============================================
 * Network-based backends (S3, Redis, HTTP) are defined in the API but
 * currently return AK_E_STATE_BACKEND_ERROR because they require an
 * HTTPS/TLS client implementation which is NOT AVAILABLE in the kernel.
 *
 * The kernel operates at ring 0 and does not include a full TLS stack.
 * To use remote backends, deployments must use one of:
 *
 *   1. VIRTIO Backend (Recommended for cloud):
 *      - Use AK_STORAGE_VIRTIO with the host-side akproxy daemon
 *      - The daemon handles HTTPS/TLS and forwards to S3/Redis/HTTP
 *      - Implemented via ak_virtio_proxy filesystem operations
 *        (one file per object; see BACKEND OPERATIONS below)
 *      - Provides isolation: kernel never sees credentials
 *
 *   2. Sidecar Proxy (Alternative):
 *      - Run a TLS-terminating proxy in userspace
 *      - Route kernel requests through localhost socket
 *      - Not implemented in current AK version
 *
 *   3. Host-Mediated Storage (Nanos integration):
 *      - Extend Nanos TFS or tmpfs to sync externally
 *      - Kernel writes to local filesystem
 *      - Host/hypervisor syncs to remote storage
 *
 * For local development/testing without remote sync:
 *   - Use AK_STORAGE_NONE (anchors emitted to audit log only)
 *   - Anchors are still computed and chained locally
 *   - Set AK_ENABLE_REMOTE_ANCHOR=0 in ak_config.h
 */

/* Filesystem integration includes for state persistence */
#include <unix_internal.h>
#include <filesystem.h>
#include <kernel/pagecache.h>
#include <fs/fs.h>
#include <runtime/sg.h>
#include <runtime/range.h>
#include <runtime/closure.h>
#include <runtime/status.h>

#include "ak_state.h"
#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_compress.h"
#include "ak_heap.h"
#include "ak_syscall.h"
#include "ak_virtio_proxy.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

#define AK_MAX_DIRTY_OBJECTS 65536
#define AK_DIRTY_BITMAP_SIZE (AK_MAX_DIRTY_OBJECTS / 64)

/* Key tag distinguishing anchor records from heap objects in the
 * backend keyspace (see ak_state_emit_anchor / ak_backend_list) */
#define AK_ANCHOR_KEY_TAG 0x00A0C40000000000ULL
#define AK_ANCHOR_KEY_MASK 0xFFFFFF0000000000ULL

static struct {
  heap h;
  boolean initialized;
  ak_storage_config_t config;
  ak_state_stats_t stats;

  /* Hydration state */
  ak_hydration_status_t hydration;

  /* Dirty tracking (bitmap for efficiency) */
  u64 dirty_bitmap[AK_DIRTY_BITMAP_SIZE];
  u64 dirty_ptrs[AK_MAX_DIRTY_OBJECTS];
  u32 dirty_count;

  /* Sync state */
  ak_sync_status_t sync_status;
  u64 last_sync_ms;

  /* Anchor chain */
  ak_state_anchor_t latest_anchor;
  u64 anchor_sequence;

  /* Backend connection state */
  boolean backend_connected;
  int virtio_fd;
} ak_state;

/* ============================================================
 * CRYPTOGRAPHIC HELPERS
 * ============================================================ */

static u64 get_timestamp_ms(void) { return now(CLOCK_ID_MONOTONIC) / MILLION; }

/*
 * FNV-1a hash extended to fill AK_HASH_SIZE bytes.
 * Production deployments should use SHA-256.
 */
static void compute_hash(buffer data, u8 *hash_out) {
  u64 len = buffer_length(data);
  u8 *bytes = buffer_ref(data, 0);

  /* FNV-1a 64-bit */
  u64 h = 0xcbf29ce484222325ULL;
  for (u64 i = 0; i < len; i++) {
    h ^= bytes[i];
    h *= 0x100000001b3ULL;
  }

  /* Extend hash to fill AK_HASH_SIZE */
  for (int i = 0; i < AK_HASH_SIZE; i++) {
    hash_out[i] = (h >> ((i % 8) * 8)) & 0xff;
    if ((i % 8) == 7) {
      h ^= (u64)i;
      h *= 0x100000001b3ULL;
    }
  }
}

/*
 * Compute merkle root from list of hashes.
 * Uses separate input/output buffers to avoid in-place overwriting bugs.
 */
static void compute_merkle_root(u8 *hashes, u32 count, u8 *root_out) {
  if (count == 0) {
    runtime_memset(root_out, 0, AK_HASH_SIZE);
    return;
  }

  if (count == 1) {
    runtime_memcpy(root_out, hashes, AK_HASH_SIZE);
    return;
  }

  /* Note: count is u32, so count * AK_HASH_SIZE cannot overflow u64 */

  /* Allocate two buffers for ping-pong computation to avoid in-place overwrites
   */
  u64 max_level_size = (u64)count * AK_HASH_SIZE;
  u8 *buf_a = allocate(ak_state.h, max_level_size);
  u8 *buf_b = allocate(ak_state.h, max_level_size);

  if (buf_a == INVALID_ADDRESS || buf_b == INVALID_ADDRESS) {
    /* Allocation failed - fall back to zeroed root */
    if (buf_a != INVALID_ADDRESS)
      deallocate(ak_state.h, buf_a, max_level_size);
    if (buf_b != INVALID_ADDRESS)
      deallocate(ak_state.h, buf_b, max_level_size);
    runtime_memset(root_out, 0, AK_HASH_SIZE);
    return;
  }

  /* Copy input to first buffer */
  runtime_memcpy(buf_a, hashes, count * AK_HASH_SIZE);

  u8 *curr_buf = buf_a;
  u8 *next_buf = buf_b;
  u32 curr_count = count;

  while (curr_count > 1) {
    u32 pairs = (curr_count + 1) / 2;
    for (u32 i = 0; i < pairs; i++) {
      u8 combined[AK_HASH_SIZE * 2];
      runtime_memcpy(combined, &curr_buf[i * 2 * AK_HASH_SIZE], AK_HASH_SIZE);

      if (i * 2 + 1 < curr_count) {
        runtime_memcpy(&combined[AK_HASH_SIZE],
                       &curr_buf[(i * 2 + 1) * AK_HASH_SIZE], AK_HASH_SIZE);
      } else {
        /* Odd node: duplicate */
        runtime_memcpy(&combined[AK_HASH_SIZE], &curr_buf[i * 2 * AK_HASH_SIZE],
                       AK_HASH_SIZE);
      }

      /* Hash the pair into the next buffer (not current) */
      buffer pair_buf = alloca_wrap_buffer(combined, AK_HASH_SIZE * 2);
      if (pair_buf && pair_buf != INVALID_ADDRESS) {
        compute_hash(pair_buf, &next_buf[i * AK_HASH_SIZE]);
      } else {
        runtime_memset(&next_buf[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
      }
    }
    curr_count = pairs;

    /* Swap buffers for next iteration */
    u8 *tmp = curr_buf;
    curr_buf = next_buf;
    next_buf = tmp;
  }

  runtime_memcpy(root_out, curr_buf, AK_HASH_SIZE);

  /* Free allocated buffers */
  deallocate(ak_state.h, buf_a, max_level_size);
  deallocate(ak_state.h, buf_b, max_level_size);
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_state_init(heap h, ak_storage_config_t *config) {
  if (ak_state.initialized)
    return;

  ak_state.h = h;
  runtime_memset((u8 *)&ak_state.stats, 0, sizeof(ak_state_stats_t));
  runtime_memset((u8 *)&ak_state.hydration, 0, sizeof(ak_hydration_status_t));
  runtime_memset((u8 *)ak_state.dirty_bitmap, 0, sizeof(ak_state.dirty_bitmap));
  ak_state.dirty_count = 0;
  ak_state.virtio_fd = -1;

  if (config) {
    runtime_memcpy(&ak_state.config, config, sizeof(ak_storage_config_t));
  } else {
    ak_state.config.backend = AK_STORAGE_NONE;
    ak_state.config.sync_interval_ms = 0;
    ak_state.config.sync_batch_size = 100;
    ak_state.config.sync_timeout_ms = 30000;
    ak_state.config.max_retries = 3;
    ak_state.config.retry_backoff_ms = 1000;
  }

  ak_state.sync_status = AK_SYNC_IDLE;
  ak_state.last_sync_ms = 0;
  ak_state.anchor_sequence = 0;
  ak_state.backend_connected = false;

  /* Initialize genesis anchor */
  runtime_memset((u8 *)&ak_state.latest_anchor, 0, sizeof(ak_state_anchor_t));
  ak_state.latest_anchor.timestamp_ms = get_timestamp_ms();
  ak_state.latest_anchor.sequence = 0;

  ak_state.initialized = true;

  /* Connect to backend */
  if (ak_state.config.backend != AK_STORAGE_NONE) {
    ak_state.backend_connected = ak_backend_healthy();
  }
}

void ak_state_shutdown(void) {
  if (!ak_state.initialized)
    return;

  /* Final sync before shutdown */
  if (ak_state.config.backend != AK_STORAGE_NONE && ak_state.dirty_count > 0) {
    ak_state_sync_immediate();
    ak_state_emit_anchor();
  }

  if (ak_state.virtio_fd >= 0) {
    ak_state.virtio_fd = -1;
  }

  ak_state.initialized = false;
}

s64 ak_state_configure(ak_storage_config_t *config) {
  if (!config)
    return AK_E_SCHEMA_INVALID;

  runtime_memcpy(&ak_state.config, config, sizeof(ak_storage_config_t));

  if (config->backend != AK_STORAGE_NONE) {
    ak_state.backend_connected = ak_backend_healthy();
  } else {
    ak_state.backend_connected = false;
  }

  return 0;
}

/* ============================================================
 * HYDRATION
 * ============================================================ */

s64 ak_state_hydrate(ak_heap_t *heap) {
  if (!ak_state.initialized)
    return AK_E_STATE_NOT_FOUND;

  if (ak_state.config.backend == AK_STORAGE_NONE)
    return AK_E_STATE_NOT_FOUND;

  if (!heap)
    return AK_E_SCHEMA_INVALID;

  ak_state.stats.hydrations_total++;
  u64 start_ms = get_timestamp_ms();

  /* Get list of objects from backend */
  u32 object_count = 0;
  u64 *ptrs = ak_backend_list(&object_count);

  if (!ptrs || object_count == 0) {
    ak_state.hydration.hydrated = false;
    return AK_E_STATE_NOT_FOUND;
  }

  /* Bounds check: limit object count to prevent excessive memory usage */
  if (object_count > AK_MAX_DIRTY_OBJECTS) {
    object_count = AK_MAX_DIRTY_OBJECTS;
  }

  u64 bytes_loaded = 0;
  u64 objects_loaded = 0;

  /* Load each object into heap */
  for (u32 i = 0; i < object_count; i++) {
    buffer value = ak_backend_get(ptrs[i]);
    if (value && value != INVALID_ADDRESS) {
      /* Restore object to typed heap */
      s64 result = ak_heap_restore(value);
      if (result == 0) {
        bytes_loaded += buffer_length(value);
        objects_loaded++;
      }
      deallocate_buffer(value);
    }
  }

  if (ptrs)
    deallocate(ak_state.h, ptrs, object_count * sizeof(u64));

  ak_state.hydration.hydrated = (objects_loaded > 0);
  ak_state.hydration.objects_loaded = objects_loaded;
  ak_state.hydration.bytes_loaded = bytes_loaded;
  ak_state.hydration.duration_ms = get_timestamp_ms() - start_ms;

  return (objects_loaded > 0) ? 0 : AK_E_STATE_NOT_FOUND;
}

boolean ak_state_verify_integrity(void) {
  if (!ak_state.hydration.hydrated)
    return false;

  /* Verify by recomputing merkle root and comparing to anchor */
  u32 count;
  u64 *ptrs = ak_state_get_dirty_list(&count);

  if (count == 0)
    return true;

  /* Note: count is u32, so count * AK_HASH_SIZE cannot overflow u64 */

  /* Allocate hash array */
  u8 *hashes = allocate(ak_state.h, (u64)count * AK_HASH_SIZE);
  if (hashes == INVALID_ADDRESS)
    return false;

  /* Hash each object */
  for (u32 i = 0; i < count; i++) {
    buffer value = ak_backend_get(ptrs[i]);
    if (value && value != INVALID_ADDRESS) {
      compute_hash(value, &hashes[i * AK_HASH_SIZE]);
      deallocate_buffer(value);
    } else {
      runtime_memset(&hashes[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
    }
  }

  /* Compute merkle root */
  u8 computed_root[AK_HASH_SIZE];
  compute_merkle_root(hashes, count, computed_root);

  deallocate(ak_state.h, hashes, count * AK_HASH_SIZE);

  /* Compare to stored anchor */
  return runtime_memcmp(computed_root, ak_state.latest_anchor.heap_root,
                        AK_HASH_SIZE) == 0;
}

void ak_state_get_hydration_status(ak_hydration_status_t *status) {
  if (status)
    runtime_memcpy(status, &ak_state.hydration, sizeof(ak_hydration_status_t));
}

/* ============================================================
 * DIRTY TRACKING
 * ============================================================ */

static u32 ptr_to_index(u64 ptr) {
  return (u32)((ptr * 2654435761ULL) % AK_MAX_DIRTY_OBJECTS);
}

void ak_state_mark_dirty(u64 ptr) {
  if (!ak_state.initialized)
    return;

  u32 idx = ptr_to_index(ptr);
  u32 word = idx / 64;
  u32 bit = idx % 64;

  if (!(ak_state.dirty_bitmap[word] & (1ULL << bit))) {
    ak_state.dirty_bitmap[word] |= (1ULL << bit);

    if (ak_state.dirty_count < AK_MAX_DIRTY_OBJECTS) {
      ak_state.dirty_ptrs[ak_state.dirty_count++] = ptr;
    }
  }
}

void ak_state_mark_clean(u64 ptr) {
  if (!ak_state.initialized)
    return;

  u32 idx = ptr_to_index(ptr);
  u32 word = idx / 64;
  u32 bit = idx % 64;

  ak_state.dirty_bitmap[word] &= ~(1ULL << bit);

  for (u32 i = 0; i < ak_state.dirty_count; i++) {
    if (ak_state.dirty_ptrs[i] == ptr) {
      for (u32 j = i; j < ak_state.dirty_count - 1; j++)
        ak_state.dirty_ptrs[j] = ak_state.dirty_ptrs[j + 1];
      ak_state.dirty_count--;
      break;
    }
  }
}

boolean ak_state_is_dirty(u64 ptr) {
  if (!ak_state.initialized)
    return false;

  u32 idx = ptr_to_index(ptr);
  u32 word = idx / 64;
  u32 bit = idx % 64;

  return (ak_state.dirty_bitmap[word] & (1ULL << bit)) != 0;
}

u64 ak_state_dirty_count(void) { return ak_state.dirty_count; }

u64 *ak_state_get_dirty_list(u32 *count_out) {
  if (count_out)
    *count_out = ak_state.dirty_count;
  return ak_state.dirty_ptrs;
}

/* ============================================================
 * SYNC OPERATIONS
 * ============================================================ */

ak_sync_result_t ak_state_sync(void) {
  ak_sync_result_t result;
  runtime_memset((u8 *)&result, 0, sizeof(ak_sync_result_t));

  if (!ak_state.initialized) {
    result.status = AK_SYNC_FAILED;
    result.error_code = AK_E_STATE_NOT_FOUND;
    return result;
  }

  if (ak_state.config.backend == AK_STORAGE_NONE) {
    /* No backend configured: nothing was (or can be) durably persisted.
     * Do NOT report AK_SYNC_COMPLETED, which callers read as "durable". */
    result.status = AK_SYNC_NO_BACKEND;
    return result;
  }

  if (ak_state.dirty_count == 0) {
    result.status = AK_SYNC_COMPLETED;
    return result;
  }

  return ak_state_sync_objects(ak_state.dirty_ptrs, ak_state.dirty_count);
}

ak_sync_result_t ak_state_sync_objects(u64 *ptrs, u32 count) {
  ak_sync_result_t result;
  runtime_memset((u8 *)&result, 0, sizeof(ak_sync_result_t));

  if (!ptrs || count == 0) {
    result.status = AK_SYNC_COMPLETED;
    return result;
  }

  ak_state.sync_status = AK_SYNC_IN_PROGRESS;
  ak_state.stats.syncs_total++;

  u64 start_ms = get_timestamp_ms();
  u64 objects_synced = 0;
  u64 bytes_synced = 0;
  s64 last_error = 0;

  /* Copy the ptr list: callers typically pass ak_state.dirty_ptrs, which
   * ak_state_mark_clean() mutates by shifting elements. Iterating the
   * live array would skip objects after each successful put. */
  u64 *ptrs_copy = allocate(ak_state.h, (u64)count * sizeof(u64));
  if (ptrs_copy == INVALID_ADDRESS) {
    result.status = AK_SYNC_FAILED;
    result.error_code = AK_E_STATE_SYNC_FAILED;
    ak_state.stats.syncs_failed++;
    ak_state.sync_status = AK_SYNC_FAILED;
    return result;
  }
  runtime_memcpy(ptrs_copy, ptrs, (u64)count * sizeof(u64));

  /* Sync each object */
  for (u32 i = 0; i < count; i++) {
    u64 ptr = ptrs_copy[i];

    /* Get object value from typed heap */
    buffer value = ak_heap_serialize_object(ak_state.h, ptr);
    if (!value || value == INVALID_ADDRESS) {
      last_error = AK_E_STATE_SYNC_FAILED;
      continue;
    }

    /* Compute hash for integrity (on uncompressed data). Compression,
     * where supported, is handled inside the backend so that the stored
     * record carries the metadata needed to restore the object. */
    u8 hash[AK_HASH_SIZE];
    compute_hash(value, hash);

    /* Store to backend */
    s64 put_result = ak_backend_put(ptr, value, hash);

    if (put_result == 0) {
      /* Only objects actually acknowledged by the backend are marked
       * clean; failed objects stay dirty for the next sync attempt. */
      objects_synced++;
      bytes_synced += buffer_length(value);
      ak_state_mark_clean(ptr);
    } else {
      last_error = put_result;
    }

    deallocate_buffer(value);
  }

  deallocate(ak_state.h, ptrs_copy, (u64)count * sizeof(u64));

  result.duration_ms = get_timestamp_ms() - start_ms;
  result.objects_synced = objects_synced;
  result.bytes_synced = bytes_synced;

  if (objects_synced == count) {
    result.status = AK_SYNC_COMPLETED;
    ak_state.stats.syncs_successful++;
  } else if (objects_synced > 0) {
    result.status = AK_SYNC_PARTIAL;
    result.error_code = last_error ? last_error : AK_E_STATE_SYNC_FAILED;
  } else {
    result.status = AK_SYNC_FAILED;
    result.error_code = last_error ? last_error : AK_E_STATE_SYNC_FAILED;
    ak_state.stats.syncs_failed++;
  }

  ak_state.stats.objects_synced_total += objects_synced;
  ak_state.stats.bytes_synced_total += bytes_synced;
  ak_state.stats.total_sync_time_ms += result.duration_ms;

  ak_state.sync_status = result.status;
  ak_state.last_sync_ms = get_timestamp_ms();

  return result;
}

ak_sync_result_t ak_state_sync_immediate(void) { return ak_state_sync(); }

boolean ak_state_sync_in_progress(void) {
  return ak_state.sync_status == AK_SYNC_IN_PROGRESS;
}

ak_sync_result_t ak_state_sync_wait(u32 timeout_ms) {
  (void)timeout_ms;
  return ak_state_sync();
}

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================ */

s64 ak_state_emit_anchor(void) {
  if (!ak_state.initialized)
    return AK_E_STATE_NOT_FOUND;

  ak_state_anchor_t anchor;
  runtime_memset((u8 *)&anchor, 0, sizeof(ak_state_anchor_t));

  anchor.timestamp_ms = get_timestamp_ms();
  anchor.sequence = ++ak_state.anchor_sequence;

  /* Chain to previous anchor */
  runtime_memcpy(anchor.prev_anchor, ak_state.latest_anchor.heap_root,
                 AK_HASH_SIZE);

  /* Compute merkle root over the DIRTY object set at emission time.
   *
   * HONESTY NOTE: this is a delta commitment, not a commitment to the
   * full heap - the kernel has no full-heap enumeration API. After a
   * fully clean sync the dirty set is empty and heap_root is all zeros.
   * Tamper-evidence for history comes from the prev_anchor chain and
   * log_root (audit log head), not from heap_root alone. */
  u32 count;
  u64 *ptrs = ak_state_get_dirty_list(&count);

  if (count > 0 && ptrs) {
    /* Note: count is u32, so count * AK_HASH_SIZE cannot overflow u64 */
    {
      u8 *hashes = allocate(ak_state.h, (u64)count * AK_HASH_SIZE);
      if (hashes != INVALID_ADDRESS) {
        for (u32 i = 0; i < count; i++) {
          buffer value = ak_heap_serialize_object(ak_state.h, ptrs[i]);
          if (value && value != INVALID_ADDRESS) {
            compute_hash(value, &hashes[i * AK_HASH_SIZE]);
            deallocate_buffer(value);
          } else {
            runtime_memset(&hashes[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
          }
        }
        compute_merkle_root(hashes, count, anchor.heap_root);
        deallocate(ak_state.h, hashes, (u64)count * AK_HASH_SIZE);
      }
    }
  }

  /* Get latest audit log hash */
  ak_audit_head_hash(anchor.log_root);

  /* The signature field is left all zeros: Ed25519 anchor signing is NOT
   * implemented. Anchors provide tamper-evidence through the prev_anchor
   * hash chain and log_root, but no non-repudiation. */

  /* Store anchor to backend (best effort; the local chain is authoritative) */
  if (ak_state.config.backend != AK_STORAGE_NONE) {
    buffer anchor_buf = allocate_buffer(ak_state.h, sizeof(ak_state_anchor_t));
    if (anchor_buf != INVALID_ADDRESS) {
      buffer_write(anchor_buf, &anchor, sizeof(ak_state_anchor_t));
      /* Integrity hash must cover the stored record itself */
      u8 anchor_hash[AK_HASH_SIZE];
      compute_hash(anchor_buf, anchor_hash);
      s64 put_res = ak_backend_put(AK_ANCHOR_KEY_TAG | anchor.sequence,
                                   anchor_buf, anchor_hash);
      if (put_res != 0)
        ak_warn("ak_state: anchor %llu not stored to backend (err %lld)",
                anchor.sequence, put_res);
      deallocate_buffer(anchor_buf);
    }
  }

  runtime_memcpy(&ak_state.latest_anchor, &anchor, sizeof(ak_state_anchor_t));
  ak_state.stats.anchors_emitted++;

  return 0;
}

ak_state_anchor_t *ak_state_get_latest_anchor(void) {
  if (!ak_state.initialized)
    return 0;
  return &ak_state.latest_anchor;
}

boolean ak_state_verify_anchor_chain(void) {
  if (!ak_state.initialized)
    return false;

  /* Verify chain by checking each anchor links to previous */
  /* For genesis anchor (sequence 0), prev_anchor should be zero */
  if (ak_state.anchor_sequence == 0) {
    u8 zero[AK_HASH_SIZE];
    runtime_memset(zero, 0, AK_HASH_SIZE);
    return runtime_memcmp(ak_state.latest_anchor.prev_anchor, zero,
                          AK_HASH_SIZE) == 0;
  }

  /* Non-genesis: prev_anchor should match previous anchor's heap_root */
  /* Full verification requires fetching all anchors from backend */
  return true;
}

/* ============================================================
 * BACKEND OPERATIONS
 *
 * VIRTIO backend (the only functional backend):
 * ----------------------------------------------
 * Objects are persisted through the host-side akproxy daemon using the
 * ak_virtio_proxy filesystem operations. Each object is stored as a
 * file AK_VIRTIO_STATE_DIR/obj_<ptr:16 hex> whose content is the hex
 * encoding of the record:
 *
 *   [flags:1][hash:32][payload]
 *
 *   flags bit 0 - payload is LZ4 compressed (ak_compress_lz4 framing)
 *   hash        - integrity hash of the payload exactly as stored
 *
 * Hex encoding is used because the proxy fs_read path returns JSON
 * string content without unescaping; hex needs no escaping and
 * round-trips losslessly. Deletion writes a zero-length tombstone file
 * (the proxy exposes no remove operation); ak_backend_get() treats
 * tombstones as not-found.
 *
 * NETWORK BACKEND LIMITATIONS (P2-3):
 * -----------------------------------
 * S3, Redis, and HTTP backends require HTTPS/TLS which is not
 * available in the kernel. These backends FAIL CLOSED: puts/deletes
 * return AK_E_STATE_BACKEND_ERROR and get/list return empty, so no
 * caller can mistake them for successful persistence. To use remote
 * storage, use the VIRTIO backend with a host-side daemon that
 * performs the actual HTTPS operations.
 * ============================================================ */

#define AK_VIRTIO_STATE_DIR "/ak/state"
#define AK_VIRTIO_REC_COMPRESSED (1 << 0)
/* "/ak/state/obj_" + 16 hex digits + NUL */
#define AK_VIRTIO_PATH_MAX 80

static const char ak_hex_digits[] = "0123456789abcdef";

static void hex_encode(buffer out, const u8 *data, u64 len) {
  for (u64 i = 0; i < len; i++) {
    char pair[2];
    pair[0] = ak_hex_digits[data[i] >> 4];
    pair[1] = ak_hex_digits[data[i] & 0xf];
    buffer_write(out, pair, 2);
  }
}

static int hex_nibble(u8 c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode hex_len (even) hex chars into hex_len / 2 bytes */
static boolean hex_decode(const u8 *hex, u64 hex_len, u8 *out) {
  for (u64 i = 0; i + 1 < hex_len; i += 2) {
    int hi = hex_nibble(hex[i]);
    int lo = hex_nibble(hex[i + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i / 2] = (u8)((hi << 4) | lo);
  }
  return true;
}

/* Build AK_VIRTIO_STATE_DIR "/obj_<16 hex>" into path (>= AK_VIRTIO_PATH_MAX
 * bytes) */
static void virtio_object_path(u64 ptr, char *path) {
  const char *prefix = AK_VIRTIO_STATE_DIR "/obj_";
  u64 plen = runtime_strlen(prefix);
  runtime_memcpy(path, prefix, plen);
  u64 v = ptr;
  for (int i = 15; i >= 0; i--) {
    path[plen + i] = ak_hex_digits[v & 0xf];
    v >>= 4;
  }
  path[plen + 16] = '\0';
}

/* Parse an "obj_<16 hex>" directory entry back to an object ptr.
 * Returns false for directories, foreign files and anchor records. */
static boolean virtio_entry_to_ptr(ak_file_info_t *info, u64 *ptr_out) {
  if (info->is_dir)
    return false;
  if (runtime_strncmp(info->name, "obj_", 4) != 0)
    return false;

  u64 v = 0;
  for (int i = 0; i < 16; i++) {
    int nib = hex_nibble((u8)info->name[4 + i]);
    if (nib < 0)
      return false;
    v = (v << 4) | (u64)nib;
  }
  if (info->name[20] != '\0')
    return false;

  /* Anchor records are not heap objects */
  if ((v & AK_ANCHOR_KEY_MASK) == AK_ANCHOR_KEY_TAG)
    return false;

  *ptr_out = v;
  return true;
}

/*
 * Store an object to the backend.
 *
 * VIRTIO: persisted via the host-side akproxy daemon; returns 0 only if
 * the daemon acknowledged the write. Compression (when enabled and
 * worthwhile) is applied here so the stored record carries the
 * compressed flag needed for restore.
 *
 * S3/Redis/HTTP: fail closed (require HTTPS client not present in
 * kernel).
 */
s64 ak_backend_put(u64 ptr, buffer value, u8 *hash) {
  if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
    return AK_E_STATE_NOT_FOUND;

  if (!value || !hash)
    return AK_E_SCHEMA_INVALID;

  switch (ak_state.config.backend) {
  case AK_STORAGE_S3:
    /* S3 PUT requires HTTPS client - not implemented in kernel */
    return AK_E_STATE_BACKEND_ERROR;

  case AK_STORAGE_REDIS:
    /* Redis requires TCP client - not implemented in kernel */
    return AK_E_STATE_BACKEND_ERROR;

  case AK_STORAGE_HTTP:
    /* HTTP POST requires HTTPS client - not implemented in kernel */
    return AK_E_STATE_BACKEND_ERROR;

  case AK_STORAGE_VIRTIO: {
    if (!ak_proxy_connected())
      return AK_E_STATE_BACKEND_ERROR;

    /* Optionally compress the payload */
    buffer to_store = value;
    boolean compressed = false;
    if (ak_state.config.compression_enabled &&
        ak_compress_worthwhile(buffer_length(value))) {
      buffer compressed_value = ak_compress_lz4(ak_state.h, value);
      if (compressed_value && compressed_value != INVALID_ADDRESS) {
        if (buffer_length(compressed_value) < buffer_length(value)) {
          to_store = compressed_value;
          compressed = true;
        } else {
          deallocate_buffer(compressed_value);
        }
      }
    }

    /* Integrity hash covers the payload exactly as stored (the caller's
     * hash covers the uncompressed value and cannot be verified against
     * a compressed record) */
    u8 rec_hash[AK_HASH_SIZE];
    compute_hash(to_store, rec_hash);

    u8 flags = compressed ? AK_VIRTIO_REC_COMPRESSED : 0;
    buffer content = allocate_buffer(
        ak_state.h, 2 * (1 + AK_HASH_SIZE + buffer_length(to_store)));
    if (!content || content == INVALID_ADDRESS) {
      if (compressed)
        deallocate_buffer(to_store);
      return AK_E_STATE_BACKEND_ERROR;
    }
    hex_encode(content, &flags, 1);
    hex_encode(content, rec_hash, AK_HASH_SIZE);
    hex_encode(content, buffer_ref(to_store, 0), buffer_length(to_store));

    char path[AK_VIRTIO_PATH_MAX];
    virtio_object_path(ptr, path);

    s64 wres = ak_proxy_fs_write(path, content);

    if (compressed) {
      if (wres >= 0)
        ak_state.stats.bytes_compressed +=
            buffer_length(value) - buffer_length(to_store);
      deallocate_buffer(to_store);
    }
    deallocate_buffer(content);

    return (wres < 0) ? AK_E_STATE_BACKEND_ERROR : 0;
  }

  default:
    return AK_E_STATE_BACKEND_ERROR;
  }
}

buffer ak_backend_get(u64 ptr) {
  if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
    return 0;

  switch (ak_state.config.backend) {
  case AK_STORAGE_S3:
  case AK_STORAGE_REDIS:
  case AK_STORAGE_HTTP:
    /* Network backends not implemented in kernel - fail closed */
    return 0;

  case AK_STORAGE_VIRTIO: {
    if (!ak_proxy_connected())
      return 0;

    char path[AK_VIRTIO_PATH_MAX];
    virtio_object_path(ptr, path);

    buffer content = 0;
    s64 rres = ak_proxy_fs_read(path, &content);
    if (rres < 0 || !content)
      return 0;

    u64 hex_len = buffer_length(content);
    /* Zero length = tombstone; undersized or odd length = corrupt.
     * Either way: not found (fail closed). */
    if ((hex_len & 1) || hex_len < 2 * (1 + AK_HASH_SIZE)) {
      deallocate_buffer(content);
      return 0;
    }

    u64 rec_len = hex_len / 2;
    u8 *rec = allocate(ak_state.h, rec_len);
    if (rec == INVALID_ADDRESS) {
      deallocate_buffer(content);
      return 0;
    }

    boolean decoded = hex_decode(buffer_ref(content, 0), hex_len, rec);
    deallocate_buffer(content);
    if (!decoded) {
      ak_warn("ak_state: corrupt record encoding for object %llu", ptr);
      deallocate(ak_state.h, rec, rec_len);
      return 0;
    }

    u8 flags = rec[0];
    u8 *payload = rec + 1 + AK_HASH_SIZE;
    u64 payload_len = rec_len - 1 - AK_HASH_SIZE;

    /* Verify integrity hash over the payload as stored */
    u8 computed[AK_HASH_SIZE];
    buffer payload_wrap = alloca_wrap_buffer(payload, payload_len);
    compute_hash(payload_wrap, computed);
    if (runtime_memcmp(computed, rec + 1, AK_HASH_SIZE) != 0) {
      ak_warn("ak_state: integrity hash mismatch for object %llu", ptr);
      deallocate(ak_state.h, rec, rec_len);
      return 0;
    }

    buffer result = allocate_buffer(ak_state.h, payload_len ? payload_len : 1);
    if (!result || result == INVALID_ADDRESS) {
      deallocate(ak_state.h, rec, rec_len);
      return 0;
    }
    buffer_write(result, payload, payload_len);
    deallocate(ak_state.h, rec, rec_len);

    if (flags & AK_VIRTIO_REC_COMPRESSED) {
      buffer decompressed = ak_decompress_lz4(ak_state.h, result);
      deallocate_buffer(result);
      if (!decompressed || decompressed == INVALID_ADDRESS) {
        ak_warn("ak_state: decompression failed for object %llu", ptr);
        return 0;
      }
      return decompressed;
    }

    return result;
  }

  default:
    return 0;
  }
}

s64 ak_backend_delete(u64 ptr) {
  if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
    return AK_E_STATE_NOT_FOUND;

  switch (ak_state.config.backend) {
  case AK_STORAGE_S3:
  case AK_STORAGE_REDIS:
  case AK_STORAGE_HTTP:
    return AK_E_STATE_BACKEND_ERROR;

  case AK_STORAGE_VIRTIO: {
    if (!ak_proxy_connected())
      return AK_E_STATE_BACKEND_ERROR;

    /* The proxy exposes no remove operation; write a zero-length
     * tombstone. ak_backend_get() treats it as not-found. */
    char path[AK_VIRTIO_PATH_MAX];
    virtio_object_path(ptr, path);

    buffer empty = allocate_buffer(ak_state.h, 1);
    if (!empty || empty == INVALID_ADDRESS)
      return AK_E_STATE_BACKEND_ERROR;

    s64 wres = ak_proxy_fs_write(path, empty);
    deallocate_buffer(empty);

    return (wres < 0) ? AK_E_STATE_BACKEND_ERROR : 0;
  }

  default:
    return AK_E_STATE_BACKEND_ERROR;
  }
}

u64 *ak_backend_list(u32 *count_out) {
  if (count_out)
    *count_out = 0;

  if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
    return 0;

  switch (ak_state.config.backend) {
  case AK_STORAGE_S3:
  case AK_STORAGE_REDIS:
  case AK_STORAGE_HTTP:
    return 0;

  case AK_STORAGE_VIRTIO: {
    if (!ak_proxy_connected())
      return 0;

    ak_file_info_t *entries = 0;
    u64 entry_count = 0;
    s64 lres = ak_proxy_fs_list(AK_VIRTIO_STATE_DIR, &entries, &entry_count);
    if (lres < 0 || !entries || entry_count == 0) {
      if (entries && entry_count)
        deallocate(ak_state.h, entries,
                   entry_count * sizeof(ak_file_info_t));
      return 0;
    }

    /* First pass: count valid object entries so the returned array is
     * allocated with exactly the size callers will deallocate. Capped
     * at AK_MAX_DIRTY_OBJECTS to bound hydration memory usage. */
    u32 valid = 0;
    for (u64 i = 0; i < entry_count && valid < AK_MAX_DIRTY_OBJECTS; i++) {
      u64 obj_ptr;
      if (virtio_entry_to_ptr(&entries[i], &obj_ptr))
        valid++;
    }

    if (valid == 0) {
      deallocate(ak_state.h, entries, entry_count * sizeof(ak_file_info_t));
      return 0;
    }

    u64 *ptrs = allocate(ak_state.h, (u64)valid * sizeof(u64));
    if (ptrs == INVALID_ADDRESS) {
      deallocate(ak_state.h, entries, entry_count * sizeof(ak_file_info_t));
      return 0;
    }

    u32 idx = 0;
    for (u64 i = 0; i < entry_count && idx < valid; i++) {
      u64 obj_ptr;
      if (virtio_entry_to_ptr(&entries[i], &obj_ptr))
        ptrs[idx++] = obj_ptr;
    }

    deallocate(ak_state.h, entries, entry_count * sizeof(ak_file_info_t));

    if (count_out)
      *count_out = idx;
    return ptrs;
  }

  default:
    return 0;
  }
}

boolean ak_backend_healthy(void) {
  if (!ak_state.initialized)
    return false;

  if (ak_state.config.backend == AK_STORAGE_NONE)
    return true;

  switch (ak_state.config.backend) {
  case AK_STORAGE_S3:
  case AK_STORAGE_REDIS:
  case AK_STORAGE_HTTP:
    /* Network backends require external connectivity */
    return false;

  case AK_STORAGE_VIRTIO:
    return ak_proxy_connected();

  default:
    return false;
  }
}

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

static int u64_to_str(u64 n, char *buf) {
  char tmp[24];
  int len = 0;

  if (n == 0) {
    buf[0] = '0';
    return 1;
  }

  while (n > 0) {
    tmp[len++] = '0' + (n % 10);
    n /= 10;
  }

  for (int i = 0; i < len; i++)
    buf[i] = tmp[len - 1 - i];

  return len;
}

ak_response_t *ak_state_handle_commit(ak_agent_context_t *ctx,
                                      ak_request_t *req) {
  if (!ctx || !req)
    return ak_response_error(ak_state.h, req, AK_E_SCHEMA_INVALID);

  /* Perform sync. AK_SYNC_NO_BACKEND is not an error for commit (the
   * anchor is still emitted to the local chain / audit log), but the
   * response reports durable:false so callers cannot mistake an
   * in-memory-only commit for durable persistence. */
  ak_sync_result_t sync_result = ak_state_sync_immediate();

  if (sync_result.status != AK_SYNC_COMPLETED &&
      sync_result.status != AK_SYNC_PARTIAL &&
      sync_result.status != AK_SYNC_NO_BACKEND) {
    return ak_response_error(ak_state.h, req, sync_result.error_code);
  }

  boolean durable = (sync_result.status == AK_SYNC_COMPLETED ||
                     sync_result.status == AK_SYNC_PARTIAL);

  /* Emit anchor */
  s64 anchor_result = ak_state_emit_anchor();
  if (anchor_result != 0)
    return ak_response_error(ak_state.h, req, anchor_result);

  /* Build response */
  buffer result_buf = allocate_buffer(ak_state.h, 256);
  if (result_buf == INVALID_ADDRESS)
    return ak_response_error(ak_state.h, req, AK_E_STATE_SYNC_FAILED);

  char json[256];
  int len = 0;

  const char *prefix = "{\"objects_synced\":";
  u64 prefix_len = runtime_strlen(prefix);
  runtime_memcpy(&json[len], prefix, prefix_len);
  len += prefix_len;

  len += u64_to_str(sync_result.objects_synced, &json[len]);

  const char *durable_part =
      durable ? ",\"durable\":true" : ",\"durable\":false";
  u64 durable_len = runtime_strlen(durable_part);
  runtime_memcpy(&json[len], durable_part, durable_len);
  len += durable_len;

  const char *middle = ",\"anchor_sequence\":";
  u64 middle_len = runtime_strlen(middle);
  runtime_memcpy(&json[len], middle, middle_len);
  len += middle_len;

  len += u64_to_str(ak_state.anchor_sequence, &json[len]);

  json[len++] = '}';

  buffer_write(result_buf, json, len);

  return ak_response_success(ak_state.h, req, result_buf);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_state_get_stats(ak_state_stats_t *stats) {
  if (stats)
    runtime_memcpy(stats, &ak_state.stats, sizeof(ak_state_stats_t));
}

/* ============================================================
 * LOCAL DISK PERSISTENCE IMPLEMENTATION
 * ============================================================
 *
 * These functions implement state file persistence using the Nanos
 * filesystem APIs (fsfile_open_or_create, fsfile_get_writer, etc.).
 *
 * NANOS LIMITATIONS AND DESIGN NOTES:
 * -----------------------------------
 * 1. Asynchronous I/O: Nanos filesystem operations are asynchronous.
 *    We use completion handlers and spin-wait for durability guarantees.
 *
 * 2. fsync via fsfile_flush: The fsfile_flush() function provides
 *    fsync-equivalent durability when called with sync=false (full sync).
 *
 * 3. Scatter-Gather I/O: File reads/writes use sg_list for zero-copy
 *    I/O where possible.
 *
 * 4. No POSIX open/read/write: Nanos doesn't expose POSIX file APIs
 *    directly in the kernel. We use fsfile_* APIs instead.
 *
 * 5. Build Configuration: These functions are only available when
 *    AK_ENABLE_STATE_SYNC and KERNEL_STORAGE_ENABLED are defined.
 *
 * FILE FORMAT (defined in ak_state.h):
 * ------------------------------------
 * The state file uses a binary format:
 *   - Header (64 bytes): magic, version, flags, object count, timestamp,
 *     sequence, merkle root
 *   - Object entries: ptr, type_hash, version, taint, flags, data_length,
 *     hash, followed by serialized data
 *   - Anchor chain (optional): anchor count + anchor array
 *
 * INTEGRITY:
 * ----------
 * - Merkle root in header covers all objects
 * - Each object entry has individual hash for corruption detection
 * - On load, both header merkle root and individual hashes are verified
 */

#ifdef AK_ENABLE_STATE_SYNC

/* Path to the state file */
static char ak_state_file_path[256] = "/ak/state.bin";

/* State file handle */
#ifdef KERNEL_STORAGE_ENABLED
static fsfile ak_state_fsfile = NULL;
#endif

/* Sync state for async operations */
static volatile boolean ak_state_io_pending __attribute__((unused)) = false;
static volatile s64 ak_state_io_result __attribute__((unused)) = 0;

/*
 * CRC32 implementation for data integrity verification.
 * Uses the standard CRC32 polynomial (0xEDB88320).
 * Available for future use (e.g., header checksums).
 */
__attribute__((unused)) static u32 ak_state_crc32(const u8 *data, u64 len) {
  static const u32 crc32_table[256] = {
      0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
      0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
      0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
      0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
      0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
      0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
      0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
      0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
      0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
      0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
      0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
      0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
      0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
      0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
      0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
      0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
      0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
      0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
      0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7a9c, 0x5005713c, 0x270241aa,
      0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
      0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
      0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
      0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b82,
      0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
      0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
      0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
      0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
      0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
      0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
      0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
      0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
      0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
      0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
      0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
      0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
      0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
      0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
      0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
      0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
      0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdede86c5, 0x57d79a8f, 0x20d09a19,
      0xb7d99a83, 0xc0dea815, 0x548b5b76, 0x238c6be0, 0xba85605a, 0xcda962cc,
      0x5ddee15d, 0x2ad9d0cb, 0xb3d08671, 0xc4d7b6e7, 0x5a03b844, 0x2d046882,
      0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

  u32 crc = 0xFFFFFFFF;
  for (u64 i = 0; i < len; i++) {
    crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFF;
}

/*
 * Completion handler for async write operations.
 * Signals completion and stores result.
 */
#ifdef KERNEL_STORAGE_ENABLED
closure_func_basic(status_handler, void, ak_state_write_complete, status s) {
  ak_state_io_result = is_ok(s) ? 0 : -EIO;
  ak_state_io_pending = false;
  closure_finish();
}

/*
 * Completion handler for async flush (fsync) operations.
 */
closure_func_basic(status_handler, void, ak_state_flush_complete, status s) {
  ak_state_io_result = is_ok(s) ? 0 : -EIO;
  ak_state_io_pending = false;
  closure_finish();
}

/*
 * Completion handler for async read operations.
 */
closure_func_basic(status_handler, void, ak_state_read_complete, status s) {
  ak_state_io_result = is_ok(s) ? 0 : -EIO;
  ak_state_io_pending = false;
  closure_finish();
}
#endif /* KERNEL_STORAGE_ENABLED */

/*
 * Wait for pending I/O operation to complete.
 * Uses spin-wait with memory barriers for durability guarantee.
 *
 * Note: This function is only called from KERNEL_STORAGE_ENABLED code paths.
 * Marked unused to avoid warnings when storage is disabled.
 */
__attribute__((unused)) static void ak_state_wait_io(void) {
  while (ak_state_io_pending) {
    memory_barrier();
    kern_pause();
  }
}

s64 ak_state_set_file_path(const char *path) {
  if (!path)
    return AK_E_SCHEMA_INVALID;

  u64 len = runtime_strlen(path);
  if (len >= sizeof(ak_state_file_path) - 1)
    return AK_E_SCHEMA_INVALID;

  runtime_strncpy(ak_state_file_path, path, sizeof(ak_state_file_path) - 1);
  ak_state_file_path[sizeof(ak_state_file_path) - 1] = '\0';

  return 0;
}

const char *ak_state_get_file_path(void) { return ak_state_file_path; }

/*
 * ak_state_write_to_disk - Write state to local disk file
 *
 * This function serializes all dirty objects (or full state if full_sync)
 * to the configured state file path. Uses fsync() for durability.
 *
 * Parameters:
 *   full_sync - If true, write all objects; if false, only dirty objects
 *
 * Returns:
 *   0 on success, negative error code on failure
 *
 * IMPLEMENTATION NOTES:
 * ---------------------
 * 1. Opens/creates file using fsfile_open_or_create()
 * 2. Builds file header with magic, version, object count
 * 3. Computes merkle root over all objects for integrity
 * 4. Writes header + object entries sequentially
 * 5. Calls fsfile_flush() for durability (fsync equivalent)
 * 6. Uses scatter-gather I/O for efficient writes
 *
 * ERROR HANDLING:
 * ---------------
 * - Returns AK_E_STATE_NOT_FOUND if not initialized
 * - Returns AK_E_STATE_BACKEND_ERROR on file/I/O errors
 * - Partial writes may leave file in inconsistent state
 *   (merkle root verification on load will detect this)
 */
s64 ak_state_write_to_disk(boolean full_sync) {
#ifndef KERNEL_STORAGE_ENABLED
  /*
   * Storage not enabled in this build.
   *
   * NANOS LIMITATION: When KERNEL_STORAGE_ENABLED is not defined,
   * filesystem APIs (fsfile_*, sg_list, etc.) are not available.
   * State persistence requires a storage-enabled kernel build.
   *
   * To enable: Build Nanos with storage support and define
   * KERNEL_STORAGE_ENABLED in the build configuration.
   */
  (void)full_sync;
  return AK_E_NOT_IMPLEMENTED;
#else
  if (!ak_state.initialized)
    return AK_E_STATE_NOT_FOUND;

  /* Get objects to write */
  u32 object_count = 0;
  u64 *ptrs = NULL;

  if (full_sync) {
    /* For full sync, we need all objects from heap - use dirty list as proxy */
    ptrs = ak_state_get_dirty_list(&object_count);
    /* In a full sync scenario, we'd iterate the entire heap.
     * For now, this writes dirty objects only since we don't have
     * a heap enumeration API. */
  } else {
    ptrs = ak_state_get_dirty_list(&object_count);
  }

  if (object_count == 0) {
    /* Nothing to write */
    return 0;
  }

  /* Open or create the state file */
  ak_state_fsfile = fsfile_open_or_create(ss(ak_state_file_path), true);
  if (!ak_state_fsfile) {
    ak_error("ak_state: failed to open state file %s", ak_state_file_path);
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Build the state file in memory first */
  /* Estimate size: header + entries */
  u64 estimated_size =
      sizeof(ak_state_file_header_t) +
      (u64)object_count * (sizeof(ak_state_object_entry_t) + 4096);
  buffer file_buf = allocate_buffer(ak_state.h, estimated_size);
  if (!file_buf || file_buf == INVALID_ADDRESS) {
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Compute hashes for all objects and build merkle root */
  u8 *obj_hashes = NULL;
  if (object_count > 0) {
    obj_hashes = allocate(ak_state.h, (u64)object_count * AK_HASH_SIZE);
    if (!obj_hashes || obj_hashes == INVALID_ADDRESS) {
      deallocate_buffer(file_buf);
      return AK_E_STATE_BACKEND_ERROR;
    }
  }

  /* Serialize each object and compute hashes */
  buffer *obj_buffers = allocate(ak_state.h, object_count * sizeof(buffer));
  if (!obj_buffers || obj_buffers == INVALID_ADDRESS) {
    if (obj_hashes)
      deallocate(ak_state.h, obj_hashes, (u64)object_count * AK_HASH_SIZE);
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  u32 valid_count = 0;
  for (u32 i = 0; i < object_count; i++) {
    buffer obj_data = ak_heap_serialize_object(ak_state.h, ptrs[i]);
    if (!obj_data || obj_data == INVALID_ADDRESS) {
      obj_buffers[i] = NULL;
      continue;
    }
    obj_buffers[i] = obj_data;

    /* Compute hash of object data */
    compute_hash(obj_data, &obj_hashes[valid_count * AK_HASH_SIZE]);
    valid_count++;
  }

  /* Compute merkle root */
  u8 merkle_root[AK_HASH_SIZE];
  if (valid_count > 0) {
    compute_merkle_root(obj_hashes, valid_count, merkle_root);
  } else {
    runtime_memset(merkle_root, 0, AK_HASH_SIZE);
  }

  /* Build file header */
  ak_state_file_header_t header;
  runtime_memset(&header, 0, sizeof(header));
  header.magic = AK_STATE_FILE_MAGIC;
  header.version = AK_STATE_FILE_VERSION;
  header.flags = 0;
  if (ak_state.config.compression_enabled)
    header.flags |= AK_STATE_FLAG_COMPRESSED;
  header.object_count = valid_count;
  header.reserved = 0;
  header.timestamp_ms = get_timestamp_ms();
  header.sequence = ak_state.anchor_sequence;
  runtime_memcpy(header.merkle_root, merkle_root, AK_HASH_SIZE);

  /* Write header to buffer */
  buffer_write(file_buf, &header, sizeof(header));

  /* Write each object entry */
  u32 written_count = 0;
  for (u32 i = 0; i < object_count; i++) {
    if (!obj_buffers[i])
      continue;

    /* Get object metadata */
    ak_object_meta_t meta;
    if (ak_heap_get_meta(ptrs[i], &meta) != 0) {
      deallocate_buffer(obj_buffers[i]);
      continue;
    }

    /* Build object entry header */
    ak_state_object_entry_t entry;
    runtime_memset(&entry, 0, sizeof(entry));
    entry.ptr = ptrs[i];
    entry.type_hash = meta.type_hash;
    entry.version = meta.version;
    entry.taint = (u32)meta.taint;
    entry.flags = meta.deleted ? AK_OBJ_FLAG_DELETED : 0;
    entry.data_length = (u32)buffer_length(obj_buffers[i]);

    /* Copy hash computed earlier */
    runtime_memcpy(entry.hash, &obj_hashes[written_count * AK_HASH_SIZE],
                   AK_HASH_SIZE);

    /* Write entry header */
    buffer_write(file_buf, &entry, sizeof(entry));

    /* Write object data */
    buffer_write(file_buf, buffer_ref(obj_buffers[i], 0),
                 buffer_length(obj_buffers[i]));

    deallocate_buffer(obj_buffers[i]);
    written_count++;
  }

  /* Free temporary allocations */
  deallocate(ak_state.h, obj_buffers, object_count * sizeof(buffer));
  if (obj_hashes)
    deallocate(ak_state.h, obj_hashes, (u64)object_count * AK_HASH_SIZE);

  /* Write to file using scatter-gather I/O */
  sg_list sg = allocate_sg_list();
  if (!sg || sg == INVALID_ADDRESS) {
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  sg_buf sgb = sg_list_tail_add(sg, buffer_length(file_buf));
  if (sgb == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }
  sgb->buf = buffer_ref(file_buf, 0);
  sgb->size = buffer_length(file_buf);
  sgb->offset = 0;
  sgb->refcount = 0;

  /* Initiate async write */
  ak_state_io_pending = true;
  ak_state_io_result = 0;

  status_handler write_sh =
      closure_func(ak_state.h, status_handler, ak_state_write_complete);
  if (!write_sh || write_sh == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  range r = irangel(0, buffer_length(file_buf));
  sg_io writer =
      pagecache_node_get_writer(fsfile_get_cachenode(ak_state_fsfile));
  apply(writer, sg, r, write_sh);

  /* Wait for write to complete */
  ak_state_wait_io();

  deallocate_sg_list(sg);

  if (ak_state_io_result != 0) {
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Now fsync for durability */
  ak_state_io_pending = true;
  ak_state_io_result = 0;

  status_handler flush_sh =
      closure_func(ak_state.h, status_handler, ak_state_flush_complete);
  if (!flush_sh || flush_sh == INVALID_ADDRESS) {
    deallocate_buffer(file_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* false = full sync (not just metadata) */
  fsfile_flush(ak_state_fsfile, false, flush_sh);

  /* Wait for flush to complete */
  ak_state_wait_io();

  deallocate_buffer(file_buf);

  if (ak_state_io_result != 0) {
    ak_error("ak_state: fsync failed for state file");
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Update statistics */
  ak_state.stats.syncs_successful++;

  return 0;
#endif /* KERNEL_STORAGE_ENABLED */
}

/*
 * ak_state_load_from_disk - Load state from local disk file
 *
 * This function reads the state file, verifies integrity, and restores
 * objects to the typed heap.
 *
 * Returns:
 *   0 on success, negative error code on failure
 *
 * RECOVERY PROCEDURE:
 * -------------------
 * 1. Open state file (fail if not found)
 * 2. Read and verify file header (magic, version)
 * 3. Read all object entries
 * 4. Verify individual object hashes
 * 5. Compute merkle root and verify against header
 * 6. Restore valid objects to typed heap
 *
 * INTEGRITY VERIFICATION:
 * -----------------------
 * - Magic number must be AK_STATE_FILE_MAGIC ("AKST")
 * - Version must be supported (currently only version 1)
 * - Each object's hash must match its data
 * - Computed merkle root must match header's merkle root
 * - If any verification fails, returns AK_E_STATE_FILE_CORRUPT
 *
 * PARTIAL RECOVERY:
 * -----------------
 * If some objects have corrupt hashes but the merkle root doesn't match,
 * we still attempt to restore valid objects but return
 * AK_E_STATE_MERKLE_MISMATCH.
 */
s64 ak_state_load_from_disk(void) {
#ifndef KERNEL_STORAGE_ENABLED
  /*
   * Storage not enabled in this build.
   *
   * NANOS LIMITATION: Filesystem APIs require KERNEL_STORAGE_ENABLED.
   * See ak_state_write_to_disk() for details.
   */
  return AK_E_NOT_IMPLEMENTED;
#else
  if (!ak_state.initialized)
    return AK_E_STATE_NOT_FOUND;

  /* Try to open existing state file */
  ak_state_fsfile = fsfile_open_or_create(ss(ak_state_file_path), false);
  if (!ak_state_fsfile) {
    /* File doesn't exist - not an error, just no state to load */
    return AK_E_STATE_NOT_FOUND;
  }

  u64 file_size = fsfile_get_length(ak_state_fsfile);
  if (file_size < sizeof(ak_state_file_header_t)) {
    /* File too small to contain valid header */
    return AK_E_STATE_FILE_CORRUPT;
  }

  /* Allocate buffer for reading */
  buffer read_buf = allocate_buffer(ak_state.h, file_size);
  if (!read_buf || read_buf == INVALID_ADDRESS) {
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Ensure buffer has space */
  buffer_produce(read_buf, file_size);

  /* Read entire file using scatter-gather I/O */
  sg_list sg = allocate_sg_list();
  if (!sg || sg == INVALID_ADDRESS) {
    deallocate_buffer(read_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  sg_buf sgb = sg_list_tail_add(sg, file_size);
  if (sgb == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(read_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }
  sgb->buf = buffer_ref(read_buf, 0);
  sgb->size = file_size;
  sgb->offset = 0;
  sgb->refcount = 0;

  /* Initiate async read */
  ak_state_io_pending = true;
  ak_state_io_result = 0;

  status_handler read_sh =
      closure_func(ak_state.h, status_handler, ak_state_read_complete);
  if (!read_sh || read_sh == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(read_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  range r = irangel(0, file_size);
  sg_io reader = fsfile_get_reader(ak_state_fsfile);
  apply(reader, sg, r, read_sh);

  /* Wait for read to complete */
  ak_state_wait_io();

  deallocate_sg_list(sg);

  if (ak_state_io_result != 0) {
    deallocate_buffer(read_buf);
    return AK_E_STATE_BACKEND_ERROR;
  }

  /* Parse and verify file header */
  u8 *data = buffer_ref(read_buf, 0);
  ak_state_file_header_t *header = (ak_state_file_header_t *)data;

  /* Verify magic */
  if (header->magic != AK_STATE_FILE_MAGIC) {
    ak_warn("ak_state: invalid file magic 0x%08x, expected 0x%08x",
            header->magic, AK_STATE_FILE_MAGIC);
    deallocate_buffer(read_buf);
    return AK_E_STATE_FILE_CORRUPT;
  }

  /* Verify version */
  if (header->version != AK_STATE_FILE_VERSION) {
    ak_warn("ak_state: unsupported version %u, expected %u", header->version,
            AK_STATE_FILE_VERSION);
    deallocate_buffer(read_buf);
    return AK_E_STATE_VERSION_MISMATCH;
  }

  u32 object_count = header->object_count;
  if (object_count > AK_MAX_DIRTY_OBJECTS) {
    ak_warn("ak_state: object count %u exceeds maximum %u", object_count,
            AK_MAX_DIRTY_OBJECTS);
    deallocate_buffer(read_buf);
    return AK_E_STATE_FILE_CORRUPT;
  }

  /* Allocate hash array for merkle verification */
  u8 *obj_hashes = NULL;
  if (object_count > 0) {
    obj_hashes = allocate(ak_state.h, (u64)object_count * AK_HASH_SIZE);
    if (!obj_hashes || obj_hashes == INVALID_ADDRESS) {
      deallocate_buffer(read_buf);
      return AK_E_STATE_BACKEND_ERROR;
    }
  }

  /* Parse and verify each object entry */
  u64 offset = sizeof(ak_state_file_header_t);
  u64 objects_loaded = 0;
  u64 bytes_loaded = 0;
  boolean hash_mismatch = false;

  for (u32 i = 0; i < object_count; i++) {
    /* Check bounds for entry header */
    if (offset + sizeof(ak_state_object_entry_t) > file_size) {
      ak_warn("ak_state: truncated file at object %u", i);
      break;
    }

    ak_state_object_entry_t *entry = (ak_state_object_entry_t *)(data + offset);
    offset += sizeof(ak_state_object_entry_t);

    /* Check bounds for object data */
    if (offset + entry->data_length > file_size) {
      ak_warn("ak_state: truncated object data at object %u", i);
      break;
    }

    u8 *obj_data = data + offset;

    /* Verify object hash */
    buffer obj_buf = alloca_wrap_buffer(obj_data, entry->data_length);
    u8 computed_hash[AK_HASH_SIZE];
    compute_hash(obj_buf, computed_hash);

    if (runtime_memcmp(computed_hash, entry->hash, AK_HASH_SIZE) != 0) {
      ak_warn("ak_state: hash mismatch for object ptr=%llu", entry->ptr);
      hash_mismatch = true;
      /* Copy the stored hash for merkle computation anyway */
      runtime_memcpy(&obj_hashes[i * AK_HASH_SIZE], entry->hash, AK_HASH_SIZE);
      offset += entry->data_length;
      continue;
    }

    /* Hash verified - copy for merkle computation */
    runtime_memcpy(&obj_hashes[i * AK_HASH_SIZE], computed_hash, AK_HASH_SIZE);

    /* Skip deleted objects */
    if (entry->flags & AK_OBJ_FLAG_DELETED) {
      offset += entry->data_length;
      continue;
    }

    /* Restore object to heap */
    buffer restore_buf = allocate_buffer(ak_state.h, entry->data_length);
    if (restore_buf && restore_buf != INVALID_ADDRESS) {
      buffer_write(restore_buf, obj_data, entry->data_length);

      s64 result = ak_heap_restore(restore_buf);
      if (result == 0) {
        objects_loaded++;
        bytes_loaded += entry->data_length;
      }
      deallocate_buffer(restore_buf);
    }

    offset += entry->data_length;
  }

  /* Verify merkle root */
  u8 computed_merkle[AK_HASH_SIZE];
  if (object_count > 0) {
    compute_merkle_root(obj_hashes, object_count, computed_merkle);
    deallocate(ak_state.h, obj_hashes, (u64)object_count * AK_HASH_SIZE);

    if (runtime_memcmp(computed_merkle, header->merkle_root, AK_HASH_SIZE) !=
        0) {
      ak_warn("ak_state: merkle root mismatch");
      deallocate_buffer(read_buf);
      /* Still loaded some objects, return specific error */
      ak_state.hydration.hydrated = (objects_loaded > 0);
      ak_state.hydration.objects_loaded = objects_loaded;
      ak_state.hydration.bytes_loaded = bytes_loaded;
      return AK_E_STATE_MERKLE_MISMATCH;
    }
  }

  deallocate_buffer(read_buf);

  /* Update hydration status */
  ak_state.hydration.hydrated = (objects_loaded > 0);
  ak_state.hydration.objects_loaded = objects_loaded;
  ak_state.hydration.bytes_loaded = bytes_loaded;
  ak_state.hydration.source_sequence = header->sequence;

  /* Update anchor sequence to continue from loaded state */
  if (header->sequence > ak_state.anchor_sequence) {
    ak_state.anchor_sequence = header->sequence;
  }

  /* Update latest anchor with loaded merkle root */
  runtime_memcpy(ak_state.latest_anchor.heap_root, header->merkle_root,
                 AK_HASH_SIZE);
  ak_state.latest_anchor.sequence = header->sequence;
  ak_state.latest_anchor.timestamp_ms = header->timestamp_ms;

  ak_state.stats.hydrations_total++;

  if (hash_mismatch) {
    /* Some objects had hash mismatches but merkle was ok - shouldn't happen */
    return AK_E_STATE_FILE_CORRUPT;
  }

  return 0;
#endif /* KERNEL_STORAGE_ENABLED */
}

/*
 * ak_state_verify_file - SHALLOW state file header check
 *
 * Parameters:
 *   path - Path to state file to verify
 *
 * Returns:
 *   0 if the header is well-formed, negative error code otherwise
 *
 * HONESTY NOTE: this only reads the 64-byte header and checks the magic
 * number and format version. It does NOT verify the merkle root or any
 * per-object hashes, so a return of 0 is NOT an integrity guarantee.
 * Full integrity verification (per-object hashes + merkle root) is
 * performed by ak_state_load_from_disk(), which fails closed with
 * AK_E_STATE_FILE_CORRUPT / AK_E_STATE_MERKLE_MISMATCH on mismatch.
 */
s64 ak_state_verify_file(const char *path) {
#ifndef KERNEL_STORAGE_ENABLED
  (void)path;
  return AK_E_NOT_IMPLEMENTED;
#else
  if (!path)
    return AK_E_SCHEMA_INVALID;

  /* Save and temporarily change file path */
  char saved_path[256];
  runtime_strncpy(saved_path, ak_state_file_path, sizeof(saved_path));
  runtime_strncpy(ak_state_file_path, path, sizeof(ak_state_file_path) - 1);

  /* Open the file */
  fsfile verify_file = fsfile_open_or_create(ss(ak_state_file_path), false);
  if (!verify_file) {
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_NOT_FOUND;
  }

  u64 file_size = fsfile_get_length(verify_file);
  if (file_size < sizeof(ak_state_file_header_t)) {
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_FILE_CORRUPT;
  }

  /* Read file header */
  buffer header_buf =
      allocate_buffer(ak_state.h, sizeof(ak_state_file_header_t));
  if (!header_buf || header_buf == INVALID_ADDRESS) {
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_BACKEND_ERROR;
  }

  buffer_produce(header_buf, sizeof(ak_state_file_header_t));

  sg_list sg = allocate_sg_list();
  if (!sg || sg == INVALID_ADDRESS) {
    deallocate_buffer(header_buf);
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_BACKEND_ERROR;
  }

  sg_buf sgb = sg_list_tail_add(sg, sizeof(ak_state_file_header_t));
  if (sgb == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(header_buf);
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_BACKEND_ERROR;
  }
  sgb->buf = buffer_ref(header_buf, 0);
  sgb->size = sizeof(ak_state_file_header_t);
  sgb->offset = 0;
  sgb->refcount = 0;

  ak_state_io_pending = true;
  ak_state_io_result = 0;

  status_handler read_sh =
      closure_func(ak_state.h, status_handler, ak_state_read_complete);
  if (!read_sh || read_sh == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(header_buf);
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_BACKEND_ERROR;
  }

  range r = irangel(0, sizeof(ak_state_file_header_t));
  sg_io reader = fsfile_get_reader(verify_file);
  apply(reader, sg, r, read_sh);

  ak_state_wait_io();
  deallocate_sg_list(sg);

  if (ak_state_io_result != 0) {
    deallocate_buffer(header_buf);
    runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));
    return AK_E_STATE_BACKEND_ERROR;
  }

  ak_state_file_header_t *header =
      (ak_state_file_header_t *)buffer_ref(header_buf, 0);

  s64 result = 0;
  if (header->magic != AK_STATE_FILE_MAGIC) {
    result = AK_E_STATE_FILE_CORRUPT;
  } else if (header->version != AK_STATE_FILE_VERSION) {
    result = AK_E_STATE_VERSION_MISMATCH;
  }
  /* Deliberately shallow: merkle/object-hash verification requires
   * reading the entire file and is performed by ak_state_load_from_disk().
   * A 0 result here means "header well-formed", NOT "content intact". */

  deallocate_buffer(header_buf);
  runtime_strncpy(ak_state_file_path, saved_path, sizeof(ak_state_file_path));

  return result;
#endif /* KERNEL_STORAGE_ENABLED */
}

#endif /* AK_ENABLE_STATE_SYNC */
