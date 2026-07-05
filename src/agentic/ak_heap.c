/*
 * Authority Kernel - Typed Heap Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Versioned object heap with CAS (Compare-And-Swap) semantics.
 * Provides atomic state management for agent data.
 *
 * SECURITY: All mutations are logged (INV-4 support).
 * Version control prevents lost updates.
 */

#include "ak_heap.h"
#include "ak_audit.h"

/* ============================================================
 * INTERNAL STRUCTURES
 * ============================================================ */

/* Internal object representation */
typedef struct ak_heap_object {
  u64 ptr;                           /* Object pointer/handle */
  u64 type_hash;                     /* Schema type identifier */
  u64 version;                       /* Current version (monotonic) */
  u64 created_ms;                    /* Creation timestamp */
  u64 modified_ms;                   /* Last modification timestamp */
  ak_taint_t taint;                  /* Current taint level */
  boolean deleted;                   /* Soft-delete flag */
  u8 owner_run_id[AK_TOKEN_ID_SIZE]; /* Owning run */
  buffer value;                      /* Current JSON value */
  struct ak_heap_object *next;       /* Hash chain */
} ak_heap_object_t;

/* Version history entry */
typedef struct ak_version_entry {
  u64 version;
  u64 timestamp_ms;
  buffer value;
  struct ak_version_entry *next;
} ak_version_entry_t;

/* Version history for an object */
typedef struct ak_version_history {
  u64 ptr;
  ak_version_entry_t *entries; /* Linked list, newest first */
  u64 count;
  struct ak_version_history *next;
} ak_version_history_t;

/* Schema registry entry */
typedef struct ak_schema_entry {
  u64 type_hash;
  buffer schema_json;
  struct ak_schema_entry *next;
} ak_schema_entry_t;

/* Transaction buffer entry */
typedef struct ak_txn_op {
  enum { TXN_OP_ALLOC, TXN_OP_WRITE, TXN_OP_DELETE } op_type;
  u64 ptr;
  u64 type_hash;
  buffer value; /* For ALLOC: initial value, for WRITE: patch */
  u64 expected_version;
  ak_taint_t taint;
  u8 run_id[AK_TOKEN_ID_SIZE];
  struct ak_txn_op *next;
} ak_txn_op_t;

/* Transaction structure */
struct ak_heap_txn {
  ak_txn_op_t *ops; /* Buffered operations */
  ak_txn_op_t *ops_tail;
  u64 op_count;
  boolean active;
};

/* Global heap state */
static struct {
  heap h;                     /* Memory allocator */
  ak_heap_object_t **objects; /* Hash table */
  u64 object_capacity;
  u64 object_count;
  u64 deleted_count;
  u64 next_ptr; /* Monotonic pointer generator */

  ak_version_history_t **history; /* Version history hash table */
  u64 history_capacity;
  u64 version_count;

  ak_schema_entry_t *schemas; /* Schema registry */

  /* Statistics */
  u64 bytes_used;
  u64 bytes_versions;

  boolean initialized;
} ak_heap_state;

/*
 * Global heap lock.
 *
 * SECURITY: The CAS sequence (find_object -> compare version -> mutate)
 * must be a single critical section, otherwise two concurrent writers can
 * both pass the version check and one update is silently lost. All object
 * table mutations and reads of object values are serialized on this lock.
 * On non-SMP builds spin_lock()/spin_unlock() compile down to no-ops, so
 * single-threaded behavior is unchanged.
 */
static struct spinlock heap_lock;

/* Hash table parameters */
#define AK_HEAP_INITIAL_CAPACITY 1024
#define AK_HEAP_LOAD_FACTOR 0.75

/* Forward declarations for serialization helpers (defined below) */
static void serialize_write_u64(buffer out, u64 val);
static void serialize_write_json_string(buffer out, const char *str, u64 len);
static buffer serialize_object_internal(heap h, ak_heap_object_t *obj);

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static u64 ptr_hash(u64 ptr) {
  /* Simple hash for pointer lookup */
  ptr ^= ptr >> 33;
  ptr *= 0xff51afd7ed558ccdULL;
  ptr ^= ptr >> 33;
  ptr *= 0xc4ceb9fe1a85ec53ULL;
  ptr ^= ptr >> 33;
  return ptr;
}

static ak_heap_object_t *find_object(u64 ptr) {
  if (!ak_heap_state.initialized || !ak_heap_state.objects)
    return NULL;

  u64 idx = ptr_hash(ptr) % ak_heap_state.object_capacity;
  ak_heap_object_t *obj = ak_heap_state.objects[idx];

  while (obj) {
    if (obj->ptr == ptr)
      return obj;
    obj = obj->next;
  }
  return NULL;
}

static ak_version_history_t *find_history(u64 ptr) {
  if (!ak_heap_state.history)
    return NULL;

  u64 idx = ptr_hash(ptr) % ak_heap_state.history_capacity;
  ak_version_history_t *hist = ak_heap_state.history[idx];

  while (hist) {
    if (hist->ptr == ptr)
      return hist;
    hist = hist->next;
  }
  return NULL;
}

static ak_schema_entry_t *find_schema(u64 type_hash) {
  ak_schema_entry_t *entry = ak_heap_state.schemas;
  while (entry) {
    if (entry->type_hash == type_hash)
      return entry;
    entry = entry->next;
  }
  return NULL;
}

static u64 current_time_ms(void) {
  /* Get current monotonic time in milliseconds */
  return now(CLOCK_ID_MONOTONIC) / MILLION;
}

static void save_version(u64 ptr, u64 version, buffer value) {
  if (!ak_heap_state.history)
    return;

  u64 idx = ptr_hash(ptr) % ak_heap_state.history_capacity;
  ak_version_history_t *hist = find_history(ptr);

  if (!hist) {
    hist = allocate(ak_heap_state.h, sizeof(ak_version_history_t));
    if (!hist)
      return;

    hist->ptr = ptr;
    hist->entries = NULL;
    hist->count = 0;
    hist->next = ak_heap_state.history[idx];
    ak_heap_state.history[idx] = hist;
  }

  /* Create version entry */
  ak_version_entry_t *entry =
      allocate(ak_heap_state.h, sizeof(ak_version_entry_t));
  if (!entry)
    return;

  entry->version = version;
  entry->timestamp_ms = current_time_ms();

  /* Clone value */
  u64 len = buffer_length(value);
  entry->value = allocate_buffer(ak_heap_state.h, len);
  /* FIX(BUG-020): Check allocation before inserting entry */
  if (!entry->value || entry->value == INVALID_ADDRESS) {
    deallocate(ak_heap_state.h, entry, sizeof(ak_version_entry_t));
    return; /* Don't insert entry with NULL value */
  }
  buffer_write(entry->value, buffer_ref(value, 0), len);
  ak_heap_state.bytes_versions += len;

  /* Insert at head (newest first) */
  entry->next = hist->entries;
  hist->entries = entry;
  hist->count++;
  ak_heap_state.version_count++;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_heap_init(heap h) {
  if (ak_heap_state.initialized)
    return;

  ak_heap_state.h = h;
  spin_lock_init(&heap_lock);
  ak_heap_state.object_capacity = AK_HEAP_INITIAL_CAPACITY;
  ak_heap_state.objects = allocate_zero(h, ak_heap_state.object_capacity *
                                               sizeof(ak_heap_object_t *));

  ak_heap_state.history_capacity = AK_HEAP_INITIAL_CAPACITY;
  ak_heap_state.history = allocate_zero(h, ak_heap_state.history_capacity *
                                               sizeof(ak_version_history_t *));

  ak_heap_state.object_count = 0;
  ak_heap_state.deleted_count = 0;
  ak_heap_state.next_ptr = 1; /* Start from 1, 0 is invalid */
  ak_heap_state.version_count = 0;
  ak_heap_state.schemas = NULL;
  ak_heap_state.bytes_used = 0;
  ak_heap_state.bytes_versions = 0;
  ak_heap_state.initialized = true;
}

/* ============================================================
 * CORE OPERATIONS
 * ============================================================ */

u64 ak_heap_alloc(u64 type_hash, buffer value, u8 *run_id, ak_taint_t taint) {
  if (!ak_heap_state.initialized)
    return 0;

  /* Validate against schema if registered */
  if (!ak_heap_validate_schema(type_hash, value))
    return 0;

  /* Allocate object */
  ak_heap_object_t *obj = allocate(ak_heap_state.h, sizeof(ak_heap_object_t));
  if (!obj)
    return 0;

  /* Clone value before entering the critical section */
  u64 len = buffer_length(value);
  obj->value = allocate_buffer(ak_heap_state.h, len);
  if (!obj->value || obj->value == INVALID_ADDRESS) {
    deallocate(ak_heap_state.h, obj, sizeof(ak_heap_object_t));
    return 0;
  }
  buffer_write(obj->value, buffer_ref(value, 0), len);

  /* Initialize object */
  obj->type_hash = type_hash;
  obj->version = 1;
  obj->created_ms = current_time_ms();
  obj->modified_ms = obj->created_ms;
  obj->taint = taint;
  obj->deleted = false;

  if (run_id) {
    runtime_memcpy(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE);
  } else {
    runtime_memset(obj->owner_run_id, 0, AK_TOKEN_ID_SIZE);
  }

  spin_lock(&heap_lock);

  /* Generate unique pointer */
  u64 ptr = ak_heap_state.next_ptr++;
  obj->ptr = ptr;

  /* Insert into hash table */
  u64 idx = ptr_hash(ptr) % ak_heap_state.object_capacity;
  obj->next = ak_heap_state.objects[idx];
  ak_heap_state.objects[idx] = obj;
  ak_heap_state.object_count++;
  ak_heap_state.bytes_used += len;

  /* Save initial version */
  save_version(ptr, 1, value);

  spin_unlock(&heap_lock);

  return ptr;
}

s64 ak_heap_read(u64 ptr, buffer *value_out, u64 *version_out,
                 ak_taint_t *taint_out) {
  if (!ak_heap_state.initialized)
    return -EINVAL;

  spin_lock(&heap_lock);

  ak_heap_object_t *obj = find_object(ptr);
  if (!obj || obj->deleted) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  /* Clone value for caller */
  if (value_out) {
    u64 len = buffer_length(obj->value);
    *value_out = allocate_buffer(ak_heap_state.h, len);
    if (!*value_out) {
      spin_unlock(&heap_lock);
      return -ENOMEM;
    }
    buffer_write(*value_out, buffer_ref(obj->value, 0), len);
  }

  if (version_out)
    *version_out = obj->version;

  if (taint_out)
    *taint_out = obj->taint;

  spin_unlock(&heap_lock);
  return 0;
}

s64 ak_heap_write(u64 ptr, buffer patch, u64 expected_version,
                  u64 *new_version_out) {
  if (!ak_heap_state.initialized)
    return -EINVAL;

  spin_lock(&heap_lock);

  ak_heap_object_t *obj = find_object(ptr);
  if (!obj || obj->deleted) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  /* CAS check: version must match. The check and the update below form a
   * single critical section so concurrent writers cannot both pass it. */
  if (obj->version != expected_version) {
    spin_unlock(&heap_lock);
    return AK_E_CONFLICT;
  }

  /* Apply JSON patch (RFC 6902). Fails closed on malformed patch/path. */
  buffer new_value = ak_json_patch_apply(ak_heap_state.h, obj->value, patch);
  if (!new_value) {
    spin_unlock(&heap_lock);
    return AK_E_SCHEMA_INVALID;
  }

  /* Validate result against schema */
  if (!ak_heap_validate_schema(obj->type_hash, new_value)) {
    /* Clean up */
    deallocate_buffer(new_value);
    spin_unlock(&heap_lock);
    return AK_E_SCHEMA_INVALID;
  }

  /* Save old version */
  save_version(ptr, obj->version, obj->value);

  /* Update object */
  u64 old_len = buffer_length(obj->value);
  u64 new_len = buffer_length(new_value);

  deallocate_buffer(obj->value);
  obj->value = new_value;
  obj->version++;
  obj->modified_ms = current_time_ms();

  /* Defensive underflow check for bytes_used accounting */
  if (ak_heap_state.bytes_used >= old_len) {
    ak_heap_state.bytes_used = ak_heap_state.bytes_used - old_len + new_len;
  } else {
    /* Recovery from accounting corruption: just set to new_len */
    ak_heap_state.bytes_used = new_len;
  }

  u64 new_version = obj->version;

  spin_unlock(&heap_lock);

  if (new_version_out)
    *new_version_out = new_version;

  return 0;
}

s64 ak_heap_delete(u64 ptr, u64 expected_version) {
  if (!ak_heap_state.initialized)
    return -EINVAL;

  spin_lock(&heap_lock);

  ak_heap_object_t *obj = find_object(ptr);
  if (!obj || obj->deleted) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  /* CAS check (atomic with the mutation below) */
  if (obj->version != expected_version) {
    spin_unlock(&heap_lock);
    return AK_E_CONFLICT;
  }

  /* Save final version before deletion */
  save_version(ptr, obj->version, obj->value);

  /* Soft delete (tombstone) */
  obj->deleted = true;
  obj->version++;
  obj->modified_ms = current_time_ms();

  ak_heap_state.deleted_count++;

  spin_unlock(&heap_lock);
  return 0;
}

/* ============================================================
 * OBJECT QUERIES
 * ============================================================ */

boolean ak_heap_exists(u64 ptr) {
  spin_lock(&heap_lock);
  ak_heap_object_t *obj = find_object(ptr);
  boolean exists = obj && !obj->deleted;
  spin_unlock(&heap_lock);
  return exists;
}

s64 ak_heap_get_meta(u64 ptr, ak_object_meta_t *meta_out) {
  if (!meta_out)
    return -EINVAL;

  spin_lock(&heap_lock);

  ak_heap_object_t *obj = find_object(ptr);
  if (!obj) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  meta_out->ptr = obj->ptr;
  meta_out->type_hash = obj->type_hash;
  meta_out->version = obj->version;
  meta_out->created_ms = obj->created_ms;
  meta_out->modified_ms = obj->modified_ms;
  meta_out->taint = obj->taint;
  meta_out->deleted = obj->deleted;

  spin_unlock(&heap_lock);
  return 0;
}

u64 *ak_heap_list_by_type(heap h, u64 type_hash, u64 *count_out) {
  if (!ak_heap_state.initialized || !count_out)
    return NULL;

  spin_lock(&heap_lock);

  /* First pass: count matching objects */
  u64 count = 0;
  for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
    ak_heap_object_t *obj = ak_heap_state.objects[i];
    while (obj) {
      if (obj->type_hash == type_hash && !obj->deleted)
        count++;
      obj = obj->next;
    }
  }

  if (count == 0) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Overflow check for allocation size */
  if (count > UINT64_MAX / sizeof(u64)) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Allocate result array */
  u64 *result = allocate(h, count * sizeof(u64));
  if (!result || result == INVALID_ADDRESS) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Second pass: collect pointers */
  /* FIX(BUG-008): Add bounds check for TOCTOU defense */
  u64 idx = 0;
  for (u64 i = 0; i < ak_heap_state.object_capacity && idx < count; i++) {
    ak_heap_object_t *obj = ak_heap_state.objects[i];
    while (obj && idx < count) {
      if (obj->type_hash == type_hash && !obj->deleted)
        result[idx++] = obj->ptr;
      obj = obj->next;
    }
  }

  spin_unlock(&heap_lock);

  *count_out = idx; /* Return actual count */
  return result;
}

u64 *ak_heap_list_by_run(heap h, u8 *run_id, u64 *count_out) {
  if (!ak_heap_state.initialized || !run_id || !count_out)
    return NULL;

  spin_lock(&heap_lock);

  /* First pass: count matching objects */
  u64 count = 0;
  for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
    ak_heap_object_t *obj = ak_heap_state.objects[i];
    while (obj) {
      if (!obj->deleted &&
          runtime_memcmp(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE) == 0)
        count++;
      obj = obj->next;
    }
  }

  if (count == 0) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Overflow check for allocation size */
  if (count > UINT64_MAX / sizeof(u64)) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Allocate result array */
  u64 *result = allocate(h, count * sizeof(u64));
  if (!result || result == INVALID_ADDRESS) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Second pass: collect pointers */
  /* FIX(BUG-023): Add bounds check to prevent buffer overflow if heap
   * is modified between first and second pass (TOCTOU defense) */
  u64 idx = 0;
  for (u64 i = 0; i < ak_heap_state.object_capacity && idx < count; i++) {
    ak_heap_object_t *obj = ak_heap_state.objects[i];
    while (obj && idx < count) {
      if (!obj->deleted &&
          runtime_memcmp(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE) == 0)
        result[idx++] = obj->ptr;
      obj = obj->next;
    }
  }

  spin_unlock(&heap_lock);

  *count_out = idx; /* Return actual count collected */
  return result;
}

/* ============================================================
 * VERSION HISTORY
 * ============================================================ */

s64 ak_heap_read_version(u64 ptr, u64 version, buffer *value_out) {
  if (!value_out)
    return -EINVAL;

  spin_lock(&heap_lock);

  ak_version_history_t *hist = find_history(ptr);
  if (!hist) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  ak_version_entry_t *entry = hist->entries;
  while (entry) {
    if (entry->version == version) {
      u64 len = buffer_length(entry->value);
      *value_out = allocate_buffer(ak_heap_state.h, len);
      if (!*value_out) {
        spin_unlock(&heap_lock);
        return -ENOMEM;
      }
      buffer_write(*value_out, buffer_ref(entry->value, 0), len);
      spin_unlock(&heap_lock);
      return 0;
    }
    entry = entry->next;
  }

  spin_unlock(&heap_lock);
  return -ENOENT;
}

u64 *ak_heap_list_versions(heap h, u64 ptr, u64 *count_out) {
  if (!count_out)
    return NULL;

  spin_lock(&heap_lock);

  ak_version_history_t *hist = find_history(ptr);
  if (!hist || hist->count == 0) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  /* Overflow check for allocation size */
  if (hist->count > UINT64_MAX / sizeof(u64)) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  u64 *result = allocate(h, hist->count * sizeof(u64));
  if (!result || result == INVALID_ADDRESS) {
    spin_unlock(&heap_lock);
    *count_out = 0;
    return NULL;
  }

  ak_version_entry_t *entry = hist->entries;
  u64 idx = 0;
  while (entry && idx < hist->count) {
    result[idx++] = entry->version;
    entry = entry->next;
  }

  u64 total = hist->count;
  spin_unlock(&heap_lock);

  *count_out = total;
  return result;
}

/* ============================================================
 * TAINT OPERATIONS
 * ============================================================ */

static s64 heap_set_taint_internal(u64 ptr, ak_taint_t new_taint,
                                   u64 expected_version, boolean sanitizer) {
  spin_lock(&heap_lock);

  ak_heap_object_t *obj = find_object(ptr);
  if (!obj || obj->deleted) {
    spin_unlock(&heap_lock);
    return -ENOENT;
  }

  if (obj->version != expected_version) {
    spin_unlock(&heap_lock);
    return AK_E_CONFLICT;
  }

  /*
   * SECURITY: Taint is monotonic. Unprivileged callers may only keep or
   * raise the taint level (toward AK_TAINT_UNTRUSTED, higher value = less
   * trusted). Downgrades toward trusted require the privileged sanitizer
   * entry point (ak_heap_set_taint_sanitized), used only after the value
   * has actually passed through a sanitizer.
   */
  if (!sanitizer && new_taint < obj->taint) {
    spin_unlock(&heap_lock);
    return AK_E_TAINT;
  }

  obj->taint = new_taint;
  obj->modified_ms = current_time_ms();

  spin_unlock(&heap_lock);
  return 0;
}

s64 ak_heap_set_taint(u64 ptr, ak_taint_t new_taint, u64 expected_version) {
  return heap_set_taint_internal(ptr, new_taint, expected_version, false);
}

s64 ak_heap_set_taint_sanitized(u64 ptr, ak_taint_t new_taint,
                                u64 expected_version) {
  return heap_set_taint_internal(ptr, new_taint, expected_version, true);
}

ak_taint_t ak_heap_get_taint(u64 ptr) {
  spin_lock(&heap_lock);
  ak_heap_object_t *obj = find_object(ptr);
  ak_taint_t taint = (obj && !obj->deleted)
                         ? obj->taint
                         : AK_TAINT_UNTRUSTED; /* Fail-closed */
  spin_unlock(&heap_lock);
  return taint;
}

/* ============================================================
 * SCHEMA VALIDATION
 * ============================================================ */

void ak_heap_register_schema(u64 type_hash, buffer schema_json) {
  if (!ak_heap_state.initialized)
    return;

  /* Check if already registered */
  ak_schema_entry_t *existing = find_schema(type_hash);
  if (existing) {
    /* FIX(BUG-021): Allocate new buffer BEFORE freeing old one */
    u64 len = buffer_length(schema_json);
    buffer new_buf = allocate_buffer(ak_heap_state.h, len);
    if (!new_buf || new_buf == INVALID_ADDRESS)
      return; /* Keep old schema if alloc fails */
    buffer_write(new_buf, buffer_ref(schema_json, 0), len);
    /* Only deallocate old after new succeeded */
    deallocate_buffer(existing->schema_json);
    existing->schema_json = new_buf;
    return;
  }

  /* Create new entry */
  ak_schema_entry_t *entry =
      allocate(ak_heap_state.h, sizeof(ak_schema_entry_t));
  if (!entry)
    return;

  entry->type_hash = type_hash;
  u64 len = buffer_length(schema_json);
  entry->schema_json = allocate_buffer(ak_heap_state.h, len);
  if (entry->schema_json)
    buffer_write(entry->schema_json, buffer_ref(schema_json, 0), len);

  entry->next = ak_heap_state.schemas;
  ak_heap_state.schemas = entry;
}

boolean ak_heap_validate_schema(u64 type_hash, buffer value) {
  ak_schema_entry_t *schema = find_schema(type_hash);
  if (!schema) {
    /* No schema registered - allow any value */
    return true;
  }

  /*
   * JSON Schema validation verifies:
   *   - Required fields are present
   *   - Field types match schema
   *   - Value constraints are satisfied
   *
   * Current implementation performs basic JSON syntax check.
   * Full validation requires JSON Schema library integration.
   */
  if (!value || buffer_length(value) == 0)
    return false;

  /* Basic JSON syntax validation: must start with { or [ */
  u8 *data = buffer_ref(value, 0);
  if (data[0] != '{' && data[0] != '[')
    return false;

  return true;
}

/* ============================================================
 * JSON SCANNING HELPERS
 * ============================================================
 * Minimal, allocation-free scanner over raw JSON text. Used by the
 * RFC 6902 patch engine and snapshot restore below. Follows the same
 * self-contained style as the JSON extraction helpers in ak_syscall.c
 * (the src/runtime/json.c parser is closure/tuple based and unsuitable
 * for in-place text transforms).
 */

static u64 json_skip_ws(const u8 *d, u64 len, u64 pos) {
  while (pos < len && (d[pos] == ' ' || d[pos] == '\t' || d[pos] == '\n' ||
                       d[pos] == '\r'))
    pos++;
  return pos;
}

/* Skip a JSON string. *pos must point at the opening quote. */
static boolean json_skip_string(const u8 *d, u64 len, u64 *pos) {
  u64 p = *pos;
  if (p >= len || d[p] != '"')
    return false;
  p++;
  while (p < len) {
    if (d[p] == '\\') {
      p += 2;
      continue;
    }
    if (d[p] == '"') {
      *pos = p + 1;
      return true;
    }
    p++;
  }
  return false; /* Unterminated string */
}

/* Skip any JSON value (scalar, object or array). */
static boolean json_skip_value(const u8 *d, u64 len, u64 *pos) {
  u64 p = json_skip_ws(d, len, *pos);
  if (p >= len)
    return false;

  u8 c = d[p];
  if (c == '"') {
    if (!json_skip_string(d, len, &p))
      return false;
  } else if (c == '{' || c == '[') {
    u64 depth = 0;
    boolean closed = false;
    while (p < len) {
      c = d[p];
      if (c == '"') {
        if (!json_skip_string(d, len, &p))
          return false;
        continue;
      }
      if (c == '{' || c == '[') {
        depth++;
      } else if (c == '}' || c == ']') {
        if (depth == 0)
          return false;
        depth--;
        if (depth == 0) {
          p++;
          closed = true;
          break;
        }
      }
      p++;
    }
    if (!closed)
      return false;
  } else if (c == '-' || (c >= '0' && c <= '9')) {
    p++;
    while (p < len &&
           ((d[p] >= '0' && d[p] <= '9') || d[p] == '.' || d[p] == 'e' ||
            d[p] == 'E' || d[p] == '+' || d[p] == '-'))
      p++;
  } else if (c == 't') {
    if (p + 4 > len || runtime_memcmp(&d[p], "true", 4) != 0)
      return false;
    p += 4;
  } else if (c == 'f') {
    if (p + 5 > len || runtime_memcmp(&d[p], "false", 5) != 0)
      return false;
    p += 5;
  } else if (c == 'n') {
    if (p + 4 > len || runtime_memcmp(&d[p], "null", 4) != 0)
      return false;
    p += 4;
  } else {
    return false;
  }
  *pos = p;
  return true;
}

/*
 * Scan the JSON object starting at obj_pos (after optional whitespace,
 * must be '{') for a member whose raw key bytes equal key/key_len.
 * All output parameters except found are optional (may be NULL).
 * Returns false on malformed object; *found reports key presence.
 */
static boolean json_object_find(const u8 *d, u64 len, u64 obj_pos,
                                const char *key, u64 key_len, boolean *found,
                                u64 *member_start, u64 *val_start, u64 *val_end,
                                u64 *close_pos, u64 *member_count) {
  u64 p = json_skip_ws(d, len, obj_pos);
  if (p >= len || d[p] != '{')
    return false;
  p++;
  *found = false;
  u64 count = 0;

  p = json_skip_ws(d, len, p);
  if (p < len && d[p] == '}') {
    if (close_pos)
      *close_pos = p;
    if (member_count)
      *member_count = count;
    return true;
  }

  while (p < len) {
    p = json_skip_ws(d, len, p);
    u64 mstart = p;
    if (p >= len || d[p] != '"')
      return false;
    u64 kstart = p + 1;
    if (!json_skip_string(d, len, &p))
      return false;
    u64 kend = p - 1; /* Excludes closing quote */
    p = json_skip_ws(d, len, p);
    if (p >= len || d[p] != ':')
      return false;
    p++;
    p = json_skip_ws(d, len, p);
    u64 vstart = p;
    if (!json_skip_value(d, len, &p))
      return false;
    count++;

    if (!*found && (kend - kstart) == key_len &&
        (key_len == 0 || runtime_memcmp(&d[kstart], key, key_len) == 0)) {
      *found = true;
      if (member_start)
        *member_start = mstart;
      if (val_start)
        *val_start = vstart;
      if (val_end)
        *val_end = p;
    }

    p = json_skip_ws(d, len, p);
    if (p >= len)
      return false;
    if (d[p] == ',') {
      p++;
      continue;
    }
    if (d[p] == '}') {
      if (close_pos)
        *close_pos = p;
      if (member_count)
        *member_count = count;
      return true;
    }
    return false;
  }
  return false;
}

/*
 * Scan the JSON array starting at arr_pos for element at index.
 * Output parameters other than found are optional. Returns false on
 * malformed array; *found reports whether index < element count.
 */
static boolean json_array_scan(const u8 *d, u64 len, u64 arr_pos, u64 index,
                               boolean *found, u64 *elem_start, u64 *elem_end,
                               u64 *close_pos, u64 *count_out) {
  u64 p = json_skip_ws(d, len, arr_pos);
  if (p >= len || d[p] != '[')
    return false;
  p++;
  *found = false;
  u64 count = 0;

  p = json_skip_ws(d, len, p);
  if (p < len && d[p] == ']') {
    if (close_pos)
      *close_pos = p;
    if (count_out)
      *count_out = count;
    return true;
  }

  while (p < len) {
    p = json_skip_ws(d, len, p);
    u64 estart = p;
    if (!json_skip_value(d, len, &p))
      return false;
    if (count == index) {
      *found = true;
      if (elem_start)
        *elem_start = estart;
      if (elem_end)
        *elem_end = p;
    }
    count++;
    p = json_skip_ws(d, len, p);
    if (p >= len)
      return false;
    if (d[p] == ',') {
      p++;
      continue;
    }
    if (d[p] == ']') {
      if (close_pos)
        *close_pos = p;
      if (count_out)
        *count_out = count;
      return true;
    }
    return false;
  }
  return false;
}

/* ============================================================
 * JSON PATCH (RFC 6902)
 * ============================================================ */

/* Maximum length of a single JSON Pointer segment (fail-closed above) */
#define AK_JSON_PTR_SEG_MAX 160

/*
 * Extract the next JSON Pointer (RFC 6901) reference token. *pos must
 * point at the '/' introducing the segment; on success it is advanced to
 * the next '/' or end of path. Unescapes ~0 -> '~' and ~1 -> '/'.
 */
static boolean json_pointer_next_segment(const char *path, u64 path_len,
                                         u64 *pos, char *seg, u64 seg_max,
                                         u64 *seg_len) {
  u64 p = *pos;
  if (p >= path_len || path[p] != '/')
    return false;
  p++;
  u64 n = 0;
  while (p < path_len && path[p] != '/') {
    char c = path[p];
    if (c == '~') {
      if (p + 1 >= path_len)
        return false;
      if (path[p + 1] == '0')
        c = '~';
      else if (path[p + 1] == '1')
        c = '/';
      else
        return false; /* Invalid escape: fail closed */
      p++;
    }
    if (n + 1 >= seg_max)
      return false;
    seg[n++] = c;
    p++;
  }
  seg[n] = 0;
  *seg_len = n;
  *pos = p;
  return true;
}

/* Resolved JSON Pointer target within a document */
typedef struct json_target {
  boolean whole_doc;        /* Empty pointer: target is entire document */
  boolean parent_is_object; /* Parent container type */
  boolean found;            /* Target currently exists */
  boolean is_append;        /* Array "-" index */
  u64 member_start;         /* Object: key quote; array: element start */
  u64 val_start;            /* Existing target value range */
  u64 val_end;
  u64 close_pos;    /* Parent container closing bracket */
  u64 parent_count; /* Member/element count of parent */
  u64 arr_index;    /* Array index (when parent is array) */
  char key[AK_JSON_PTR_SEG_MAX]; /* Final segment (object key) */
  u64 key_len;
} json_target_t;

/*
 * Resolve a JSON Pointer against document d[0..len). On success fills
 * *t; the final segment's parent container must exist, but the target
 * member/element itself may be absent (t->found == false), which is
 * what "add" needs. Returns false on malformed path/document.
 */
static boolean json_resolve_pointer(const u8 *d, u64 len, const char *path,
                                    u64 path_len, json_target_t *t) {
  runtime_memset((u8 *)t, 0, sizeof(*t));

  if (path_len == 0) {
    t->whole_doc = true;
    t->found = true;
    return true;
  }
  if (path[0] != '/')
    return false;

  u64 cur = 0; /* Position of current container value */
  u64 pos = 0;

  while (pos < path_len) {
    char seg[AK_JSON_PTR_SEG_MAX];
    u64 seg_len = 0;
    if (!json_pointer_next_segment(path, path_len, &pos, seg, sizeof(seg),
                                   &seg_len))
      return false;
    boolean last = (pos >= path_len);

    u64 cpos = json_skip_ws(d, len, cur);
    if (cpos >= len)
      return false;

    if (d[cpos] == '{') {
      boolean found = false;
      u64 mstart = 0, vstart = 0, vend = 0, close = 0, count = 0;
      if (!json_object_find(d, len, cpos, seg, seg_len, &found, &mstart,
                            &vstart, &vend, &close, &count))
        return false;
      if (last) {
        t->parent_is_object = true;
        t->found = found;
        t->member_start = mstart;
        t->val_start = vstart;
        t->val_end = vend;
        t->close_pos = close;
        t->parent_count = count;
        runtime_memcpy(t->key, seg, seg_len + 1);
        t->key_len = seg_len;
        return true;
      }
      if (!found)
        return false; /* Intermediate path member must exist */
      cur = vstart;
    } else if (d[cpos] == '[') {
      boolean is_append = (seg_len == 1 && seg[0] == '-');
      u64 index = 0;
      if (!is_append) {
        if (seg_len == 0 || (seg_len > 1 && seg[0] == '0'))
          return false; /* Empty or leading-zero index: fail closed */
        for (u64 i = 0; i < seg_len; i++) {
          if (seg[i] < '0' || seg[i] > '9')
            return false;
          u64 digit = seg[i] - '0';
          if (index > (UINT64_MAX - digit) / 10)
            return false;
          index = index * 10 + digit;
        }
      }
      boolean found = false;
      u64 estart = 0, eend = 0, close = 0, count = 0;
      if (!json_array_scan(d, len, cpos, is_append ? UINT64_MAX : index,
                           &found, &estart, &eend, &close, &count))
        return false;
      if (last) {
        t->parent_is_object = false;
        t->found = found;
        t->is_append = is_append;
        t->arr_index = index;
        t->member_start = estart;
        t->val_start = estart;
        t->val_end = eend;
        t->close_pos = close;
        t->parent_count = count;
        return true;
      }
      if (!found)
        return false;
      cur = estart;
    } else {
      return false; /* Cannot index into a scalar */
    }
  }
  return false;
}

/* Replace d[start..end) with ins[0..ins_len) into a fresh buffer */
static buffer json_splice(heap h, const u8 *d, u64 len, u64 start, u64 end,
                          const u8 *ins, u64 ins_len) {
  if (start > end || end > len)
    return NULL;
  buffer result = allocate_buffer(h, len - (end - start) + ins_len + 8);
  if (!result || result == INVALID_ADDRESS)
    return NULL;
  if (start > 0)
    buffer_write(result, d, start);
  if (ins_len > 0)
    buffer_write(result, ins, ins_len);
  if (end < len)
    buffer_write(result, &d[end], len - end);
  return result;
}

/*
 * Compute the byte range to delete for a "remove" op, swallowing the
 * separating comma (preceding one if present, else the trailing one).
 */
static void json_remove_range(const u8 *d, u64 len, json_target_t *t,
                              u64 *rm_start, u64 *rm_end) {
  u64 start = t->member_start;
  u64 end = t->val_end;

  u64 p = start;
  boolean prev_comma = false;
  while (p > 0) {
    p--;
    u8 c = d[p];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
      continue;
    if (c == ',') {
      prev_comma = true;
      start = p;
    }
    break;
  }
  if (!prev_comma) {
    u64 q = json_skip_ws(d, len, end);
    if (q < len && d[q] == ',')
      end = q + 1;
  }
  *rm_start = start;
  *rm_end = end;
}

/*
 * Apply a single patch operation to document d[0..len).
 * Supported ops: "add", "replace", "remove". All other ops (move, copy,
 * test, unknown) and malformed paths fail closed by returning NULL.
 */
static buffer json_apply_one_op(heap h, const u8 *d, u64 len, const char *op,
                                u64 op_len, const char *path, u64 path_len,
                                const u8 *val, u64 val_len) {
  json_target_t t;

  boolean is_add = (op_len == 3 && runtime_memcmp(op, "add", 3) == 0);
  boolean is_replace = (op_len == 7 && runtime_memcmp(op, "replace", 7) == 0);
  boolean is_remove = (op_len == 6 && runtime_memcmp(op, "remove", 6) == 0);

  if (!is_add && !is_replace && !is_remove)
    return NULL;

  if ((is_add || is_replace) && (!val || val_len == 0))
    return NULL; /* add/replace require a "value" member */

  if (!json_resolve_pointer(d, len, path, path_len, &t))
    return NULL;

  if (t.whole_doc) {
    if (is_remove)
      return NULL; /* Cannot remove the whole document */
    return json_splice(h, d, len, 0, len, val, val_len);
  }

  if (is_replace) {
    if (!t.found)
      return NULL; /* replace requires an existing target */
    return json_splice(h, d, len, t.val_start, t.val_end, val, val_len);
  }

  if (is_remove) {
    if (!t.found)
      return NULL;
    u64 rs, re;
    json_remove_range(d, len, &t, &rs, &re);
    return json_splice(h, d, len, rs, re, NULL, 0);
  }

  /* add */
  if (t.parent_is_object) {
    if (t.found) /* RFC 6902: add on an existing member replaces it */
      return json_splice(h, d, len, t.val_start, t.val_end, val, val_len);

    /* Insert '"key":value' before the closing brace */
    buffer ins = allocate_buffer(h, t.key_len + val_len + 8);
    if (!ins || ins == INVALID_ADDRESS)
      return NULL;
    if (t.parent_count > 0)
      buffer_write(ins, ",", 1);
    serialize_write_json_string(ins, t.key, t.key_len);
    buffer_write(ins, ":", 1);
    buffer_write(ins, val, val_len);
    buffer result = json_splice(h, d, len, t.close_pos, t.close_pos,
                                buffer_ref(ins, 0), buffer_length(ins));
    deallocate_buffer(ins);
    return result;
  }

  /* Array add */
  if (t.is_append || t.arr_index == t.parent_count) {
    /* Append before the closing bracket */
    buffer ins = allocate_buffer(h, val_len + 4);
    if (!ins || ins == INVALID_ADDRESS)
      return NULL;
    if (t.parent_count > 0)
      buffer_write(ins, ",", 1);
    buffer_write(ins, val, val_len);
    buffer result = json_splice(h, d, len, t.close_pos, t.close_pos,
                                buffer_ref(ins, 0), buffer_length(ins));
    deallocate_buffer(ins);
    return result;
  }
  if (t.arr_index < t.parent_count) {
    /* Insert 'value,' before the existing element */
    buffer ins = allocate_buffer(h, val_len + 4);
    if (!ins || ins == INVALID_ADDRESS)
      return NULL;
    buffer_write(ins, val, val_len);
    buffer_write(ins, ",", 1);
    buffer result = json_splice(h, d, len, t.member_start, t.member_start,
                                buffer_ref(ins, 0), buffer_length(ins));
    deallocate_buffer(ins);
    return result;
  }
  return NULL; /* Index beyond end of array: fail closed */
}

/*
 * Parse one RFC 6902 operation object at *pos in the patch buffer.
 * Extracts raw ranges of the "op" and "path" string contents and the
 * raw "value" member (any JSON). Advances *pos past the object.
 */
static boolean json_patch_parse_op(const u8 *d, u64 len, u64 *pos,
                                   u64 *op_start, u64 *op_end, u64 *path_start,
                                   u64 *path_end, u64 *val_start, u64 *val_end,
                                   boolean *has_value, boolean *has_from) {
  u64 p = json_skip_ws(d, len, *pos);
  if (p >= len || d[p] != '{')
    return false;
  p++;

  boolean have_op = false, have_path = false;
  *op_start = *op_end = *path_start = *path_end = 0;
  *val_start = *val_end = 0;
  *has_value = false;
  *has_from = false;

  p = json_skip_ws(d, len, p);
  if (p < len && d[p] == '}')
    return false; /* Empty operation object is invalid */

  while (p < len) {
    p = json_skip_ws(d, len, p);
    if (p >= len || d[p] != '"')
      return false;
    u64 kstart = p + 1;
    if (!json_skip_string(d, len, &p))
      return false;
    u64 klen = (p - 1) - kstart;
    p = json_skip_ws(d, len, p);
    if (p >= len || d[p] != ':')
      return false;
    p++;
    p = json_skip_ws(d, len, p);
    u64 vstart = p;
    if (!json_skip_value(d, len, &p))
      return false;

    if (klen == 2 && runtime_memcmp(&d[kstart], "op", 2) == 0) {
      if (d[vstart] != '"' || p - vstart < 2)
        return false;
      *op_start = vstart + 1;
      *op_end = p - 1;
      have_op = true;
    } else if (klen == 4 && runtime_memcmp(&d[kstart], "path", 4) == 0) {
      if (d[vstart] != '"' || p - vstart < 2)
        return false;
      *path_start = vstart + 1;
      *path_end = p - 1;
      have_path = true;
    } else if (klen == 5 && runtime_memcmp(&d[kstart], "value", 5) == 0) {
      *val_start = vstart;
      *val_end = p;
      *has_value = true;
    } else if (klen == 4 && runtime_memcmp(&d[kstart], "from", 4) == 0) {
      *has_from = true;
    }

    p = json_skip_ws(d, len, p);
    if (p >= len)
      return false;
    if (d[p] == ',') {
      p++;
      continue;
    }
    if (d[p] == '}') {
      *pos = p + 1;
      return have_op && have_path;
    }
    return false;
  }
  return false;
}

/*
 * Locate the RFC 6902 operations array within a patch buffer.
 *
 * Accepts either a bare array ([{...},...]) or a request envelope
 * object containing a "patch" member holding the array; the AK_SYS_WRITE
 * handler (ak_syscall.c) passes the whole request args object
 * ({"ptr":N,"version":N,"patch":[...]}) through as the patch buffer.
 * Anything else fails closed.
 */
static boolean json_patch_locate_array(const u8 *d, u64 len, u64 *arr_start,
                                       u64 *arr_end) {
  u64 pos = json_skip_ws(d, len, 0);
  if (pos >= len)
    return false;

  if (d[pos] == '[') {
    u64 end = pos;
    if (!json_skip_value(d, len, &end))
      return false;
    if (json_skip_ws(d, len, end) != len)
      return false; /* Trailing garbage */
    *arr_start = pos;
    *arr_end = end;
    return true;
  }

  if (d[pos] == '{') {
    boolean found = false;
    u64 vs = 0, ve = 0;
    if (!json_object_find(d, len, pos, "patch", 5, &found, NULL, &vs, &ve,
                          NULL, NULL) ||
        !found)
      return false;
    u64 p = json_skip_ws(d, ve, vs);
    if (p >= ve || d[p] != '[')
      return false;
    *arr_start = p;
    *arr_end = ve;
    return true;
  }

  return false;
}

buffer ak_json_patch_apply(heap h, buffer original, buffer patch) {
  if (!original || !patch)
    return NULL;

  const u8 *pd = buffer_ref(patch, 0);
  u64 plen = buffer_length(patch);

  u64 pos, plim;
  if (!json_patch_locate_array(pd, plen, &pos, &plim))
    return NULL;
  pos++; /* Past '[' */

  /* Working copy of the document */
  u64 doc_len = buffer_length(original);
  buffer doc = allocate_buffer(h, doc_len);
  if (!doc || doc == INVALID_ADDRESS)
    return NULL;
  buffer_write(doc, buffer_ref(original, 0), doc_len);

  pos = json_skip_ws(pd, plim, pos);
  if (pos < plim && pd[pos] == ']')
    return doc; /* Empty patch: no-op */

  while (pos < plim) {
    u64 op_s, op_e, path_s, path_e, val_s, val_e;
    boolean has_value, has_from;
    if (!json_patch_parse_op(pd, plim, &pos, &op_s, &op_e, &path_s, &path_e,
                             &val_s, &val_e, &has_value, &has_from))
      goto fail;
    if (has_from)
      goto fail; /* move/copy unsupported: fail closed */

    /* Escaped characters in paths are not supported: fail closed */
    for (u64 i = path_s; i < path_e; i++) {
      if (pd[i] == '\\')
        goto fail;
    }

    buffer next = json_apply_one_op(
        h, buffer_ref(doc, 0), buffer_length(doc), (const char *)&pd[op_s],
        op_e - op_s, (const char *)&pd[path_s], path_e - path_s,
        has_value ? &pd[val_s] : NULL, has_value ? val_e - val_s : 0);
    if (!next)
      goto fail;
    deallocate_buffer(doc);
    doc = next;

    pos = json_skip_ws(pd, plim, pos);
    if (pos < plim && pd[pos] == ',') {
      pos++;
      continue;
    }
    if (pos < plim && pd[pos] == ']')
      return doc;
    goto fail;
  }

fail:
  deallocate_buffer(doc);
  return NULL;
}

boolean ak_json_patch_validate(buffer patch) {
  if (!patch || buffer_length(patch) == 0)
    return false;

  const u8 *d = buffer_ref(patch, 0);
  u64 len = buffer_length(patch);

  u64 pos, lim;
  if (!json_patch_locate_array(d, len, &pos, &lim))
    return false;
  pos++; /* Past '[' */

  pos = json_skip_ws(d, lim, pos);
  if (pos < lim && d[pos] == ']')
    return true; /* Empty patch */

  while (pos < lim) {
    u64 op_s, op_e, path_s, path_e, val_s, val_e;
    boolean has_value, has_from;
    if (!json_patch_parse_op(d, lim, &pos, &op_s, &op_e, &path_s, &path_e,
                             &val_s, &val_e, &has_value, &has_from))
      return false;

    pos = json_skip_ws(d, lim, pos);
    if (pos < lim && d[pos] == ',') {
      pos++;
      continue;
    }
    if (pos < lim && d[pos] == ']')
      return true;
    return false;
  }
  return false;
}

buffer ak_json_patch_diff(heap h, buffer old_value, buffer new_value) {
  (void)h;
  (void)old_value;
  (void)new_value;

  /*
   * RFC 6902 patch generation is not implemented and has no in-tree
   * callers. Fail honestly (NULL per the header contract) instead of
   * returning a fake empty patch that would claim two different values
   * are identical.
   */
  return NULL;
}

/* ============================================================
 * GARBAGE COLLECTION
 * ============================================================ */

u64 ak_heap_purge_versions(u64 keep_count) {
  if (!ak_heap_state.initialized || !ak_heap_state.history)
    return 0;

  u64 purged = 0;

  spin_lock(&heap_lock);

  for (u64 i = 0; i < ak_heap_state.history_capacity; i++) {
    ak_version_history_t *hist = ak_heap_state.history[i];
    while (hist) {
      if (hist->count > keep_count) {
        /* Find the cut point */
        ak_version_entry_t *entry = hist->entries;
        u64 kept = 0;
        ak_version_entry_t *prev = NULL;

        while (entry && kept < keep_count) {
          prev = entry;
          entry = entry->next;
          kept++;
        }

        /* Purge remaining entries */
        if (prev)
          prev->next = NULL;

        while (entry) {
          ak_version_entry_t *next = entry->next;
          u64 len = buffer_length(entry->value);
          /* Defensive underflow check for bytes_versions accounting */
          if (ak_heap_state.bytes_versions >= len)
            ak_heap_state.bytes_versions -= len;
          else
            ak_heap_state.bytes_versions = 0;
          deallocate_buffer(entry->value);
          deallocate(ak_heap_state.h, entry, sizeof(ak_version_entry_t));
          entry = next;
          purged++;
          hist->count--;
          ak_heap_state.version_count--;
        }
      }
      hist = hist->next;
    }
  }

  spin_unlock(&heap_lock);

  return purged;
}

u64 ak_heap_purge_tombstones(u64 older_than_ms) {
  if (!ak_heap_state.initialized)
    return 0;

  u64 purged = 0;
  u64 now = current_time_ms();

  spin_lock(&heap_lock);

  for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
    ak_heap_object_t **prev_ptr = &ak_heap_state.objects[i];
    ak_heap_object_t *obj = *prev_ptr;

    while (obj) {
      if (obj->deleted && (now - obj->modified_ms) > older_than_ms) {
        /* Remove from chain */
        *prev_ptr = obj->next;
        ak_heap_object_t *to_free = obj;
        obj = obj->next;

        /* Free resources */
        u64 len = buffer_length(to_free->value);
        /* Defensive underflow check for bytes_used accounting */
        if (ak_heap_state.bytes_used >= len)
          ak_heap_state.bytes_used -= len;
        else
          ak_heap_state.bytes_used = 0;
        deallocate_buffer(to_free->value);
        deallocate(ak_heap_state.h, to_free, sizeof(ak_heap_object_t));

        ak_heap_state.deleted_count--;
        ak_heap_state.object_count--;
        purged++;
      } else {
        prev_ptr = &obj->next;
        obj = obj->next;
      }
    }
  }

  spin_unlock(&heap_lock);

  return purged;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_heap_get_stats(ak_heap_stats_t *stats) {
  if (!stats)
    return;

  spin_lock(&heap_lock);
  stats->object_count = ak_heap_state.object_count;
  stats->deleted_count = ak_heap_state.deleted_count;
  stats->version_count = ak_heap_state.version_count;
  stats->bytes_used = ak_heap_state.bytes_used;
  stats->bytes_versions = ak_heap_state.bytes_versions;
  spin_unlock(&heap_lock);
}

/* ============================================================
 * SNAPSHOT / RESTORE
 * ============================================================ */

buffer ak_heap_snapshot(heap h) {
  if (!ak_heap_state.initialized)
    return NULL;

  /*
   * Heap snapshot serialization format:
   * {
   *   "version": 1,
   *   "next_ptr": N,
   *   "object_count": N,
   *   "objects": [ <ak_heap_serialize_object output>, ... ]
   * }
   *
   * All objects (including tombstones, for audit fidelity) are included
   * so ak_heap_restore() can rebuild the full heap. Used for state
   * synchronization and crash recovery.
   */

  buffer result = allocate_buffer(h, 1024);
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  spin_lock(&heap_lock);

  buffer_write(result, "{\"version\":1,\"next_ptr\":", 24);
  serialize_write_u64(result, ak_heap_state.next_ptr);
  buffer_write(result, ",\"object_count\":", 16);
  serialize_write_u64(result, ak_heap_state.object_count);
  buffer_write(result, ",\"objects\":[", 12);

  boolean first = true;
  for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
    for (ak_heap_object_t *obj = ak_heap_state.objects[i]; obj;
         obj = obj->next) {
      buffer objbuf = serialize_object_internal(h, obj);
      if (!objbuf) {
        /* Fail closed: a partial snapshot is worse than no snapshot */
        spin_unlock(&heap_lock);
        deallocate_buffer(result);
        return NULL;
      }
      if (!first)
        buffer_write(result, ",", 1);
      first = false;
      buffer_write(result, buffer_ref(objbuf, 0), buffer_length(objbuf));
      deallocate_buffer(objbuf);
    }
  }

  spin_unlock(&heap_lock);

  buffer_write(result, "]}", 2);

  return result;
}

/*
 * Map serialized taint name back to taint level.
 * Unknown names map to AK_TAINT_UNTRUSTED (fail-closed).
 */
static ak_taint_t taint_from_string(const u8 *s, u64 len) {
  static const struct {
    const char *name;
    u64 len;
    ak_taint_t taint;
  } names[] = {
      {"trusted", 7, AK_TAINT_TRUSTED},
      {"sanitized_url", 13, AK_TAINT_SANITIZED_URL},
      {"sanitized_path", 14, AK_TAINT_SANITIZED_PATH},
      {"sanitized_sql", 13, AK_TAINT_SANITIZED_SQL},
      {"sanitized_cmd", 13, AK_TAINT_SANITIZED_CMD},
      {"sanitized_html", 14, AK_TAINT_SANITIZED_HTML},
      {"untrusted", 9, AK_TAINT_UNTRUSTED},
  };

  for (u64 i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (len == names[i].len &&
        runtime_memcmp(s, names[i].name, names[i].len) == 0)
      return names[i].taint;
  }
  return AK_TAINT_UNTRUSTED; /* Fail-closed */
}

/* Parse decimal u64 from d[start..end); rejects non-digits and overflow */
static boolean parse_u64_range(const u8 *d, u64 start, u64 end, u64 *out) {
  if (start >= end)
    return false;
  u64 v = 0;
  for (u64 i = start; i < end; i++) {
    if (d[i] < '0' || d[i] > '9')
      return false;
    u64 digit = d[i] - '0';
    if (v > (UINT64_MAX - digit) / 10)
      return false;
    v = v * 10 + digit;
  }
  *out = v;
  return true;
}

static boolean hex_nibble(u8 c, u8 *out) {
  if (c >= '0' && c <= '9')
    *out = c - '0';
  else if (c >= 'a' && c <= 'f')
    *out = c - 'a' + 10;
  else if (c >= 'A' && c <= 'F')
    *out = c - 'A' + 10;
  else
    return false;
  return true;
}

/*
 * Rebuild one heap object from its canonical JSON serialization
 * (the ak_heap_serialize_object format) found at obj_pos in d[0..len).
 * Upserts: an existing object with the same ptr is overwritten.
 *
 * Caller must hold heap_lock.
 */
static s64 restore_object_json(const u8 *d, u64 len, u64 obj_pos) {
  boolean found = false;
  u64 vs = 0, ve = 0;

  /* "ptr" (required, non-zero) */
  u64 ptr = 0;
  if (!json_object_find(d, len, obj_pos, "ptr", 3, &found, NULL, &vs, &ve,
                        NULL, NULL) ||
      !found || !parse_u64_range(d, vs, ve, &ptr) || ptr == 0)
    return AK_E_JSON_INVALID;

  /* Optional numeric fields */
  u64 type_hash = 0, version = 1, created = 0, modified = 0;
  if (json_object_find(d, len, obj_pos, "type_hash", 9, &found, NULL, &vs, &ve,
                       NULL, NULL) &&
      found)
    parse_u64_range(d, vs, ve, &type_hash);
  if (json_object_find(d, len, obj_pos, "version", 7, &found, NULL, &vs, &ve,
                       NULL, NULL) &&
      found)
    parse_u64_range(d, vs, ve, &version);
  if (json_object_find(d, len, obj_pos, "created_ms", 10, &found, NULL, &vs,
                       &ve, NULL, NULL) &&
      found)
    parse_u64_range(d, vs, ve, &created);
  if (json_object_find(d, len, obj_pos, "modified_ms", 11, &found, NULL, &vs,
                       &ve, NULL, NULL) &&
      found)
    parse_u64_range(d, vs, ve, &modified);

  /* "taint": string (unknown/missing -> untrusted, fail-closed) */
  ak_taint_t taint = AK_TAINT_UNTRUSTED;
  if (json_object_find(d, len, obj_pos, "taint", 5, &found, NULL, &vs, &ve,
                       NULL, NULL) &&
      found && ve > vs + 1 && d[vs] == '"')
    taint = taint_from_string(&d[vs + 1], ve - vs - 2);

  /* "deleted": boolean */
  boolean deleted = false;
  if (json_object_find(d, len, obj_pos, "deleted", 7, &found, NULL, &vs, &ve,
                       NULL, NULL) &&
      found)
    deleted = (ve - vs == 4 && runtime_memcmp(&d[vs], "true", 4) == 0);

  /* "owner_run_id": hex string */
  u8 run_id[AK_TOKEN_ID_SIZE];
  runtime_memset(run_id, 0, AK_TOKEN_ID_SIZE);
  if (json_object_find(d, len, obj_pos, "owner_run_id", 12, &found, NULL, &vs,
                       &ve, NULL, NULL) &&
      found && (ve - vs) == 2 + AK_TOKEN_ID_SIZE * 2 && d[vs] == '"') {
    for (u64 i = 0; i < AK_TOKEN_ID_SIZE; i++) {
      u8 hi, lo;
      if (!hex_nibble(d[vs + 1 + i * 2], &hi) ||
          !hex_nibble(d[vs + 2 + i * 2], &lo)) {
        runtime_memset(run_id, 0, AK_TOKEN_ID_SIZE);
        break;
      }
      run_id[i] = (hi << 4) | lo;
    }
  }

  /* "value" (required): raw embedded JSON */
  if (!json_object_find(d, len, obj_pos, "value", 5, &found, NULL, &vs, &ve,
                        NULL, NULL) ||
      !found || ve <= vs)
    return AK_E_JSON_INVALID;
  u64 vlen = ve - vs;

  /* Clone the value before touching heap state */
  buffer new_value = allocate_buffer(ak_heap_state.h, vlen);
  if (!new_value || new_value == INVALID_ADDRESS)
    return -ENOMEM;
  buffer_write(new_value, &d[vs], vlen);

  ak_heap_object_t *obj = find_object(ptr);
  if (obj) {
    /* Upsert: replace existing object in place */
    u64 old_len = obj->value ? buffer_length(obj->value) : 0;
    if (obj->value)
      deallocate_buffer(obj->value);
    obj->value = new_value;
    if (ak_heap_state.bytes_used >= old_len)
      ak_heap_state.bytes_used -= old_len;
    else
      ak_heap_state.bytes_used = 0;
    if (obj->deleted && !deleted)
      ak_heap_state.deleted_count--;
    else if (!obj->deleted && deleted)
      ak_heap_state.deleted_count++;
  } else {
    obj = allocate(ak_heap_state.h, sizeof(ak_heap_object_t));
    if (!obj || obj == INVALID_ADDRESS) {
      deallocate_buffer(new_value);
      return -ENOMEM;
    }
    obj->ptr = ptr;
    obj->value = new_value;

    u64 idx = ptr_hash(ptr) % ak_heap_state.object_capacity;
    obj->next = ak_heap_state.objects[idx];
    ak_heap_state.objects[idx] = obj;
    ak_heap_state.object_count++;
    if (deleted)
      ak_heap_state.deleted_count++;
  }

  ak_heap_state.bytes_used += vlen;

  obj->type_hash = type_hash;
  obj->version = version ? version : 1;
  obj->created_ms = created ? created : current_time_ms();
  obj->modified_ms = modified ? modified : obj->created_ms;
  obj->taint = taint;
  obj->deleted = deleted;
  runtime_memcpy(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE);

  /* Keep the pointer generator ahead of restored objects */
  if (ptr >= ak_heap_state.next_ptr)
    ak_heap_state.next_ptr = ptr + 1;

  return 0;
}

s64 ak_heap_restore(buffer snapshot) {
  if (!snapshot || buffer_length(snapshot) == 0)
    return -EINVAL;

  if (!ak_heap_state.initialized)
    return -EINVAL;

  /*
   * Restore heap objects from a snapshot. Accepts either:
   *   - a full snapshot ({"next_ptr":N,...,"objects":[{...},...]}), or
   *   - a single serialized object ({"ptr":N,...,"value":...}), as
   *     produced by ak_heap_serialize_object() and stored per-object
   *     by ak_state.c.
   *
   * Objects are upserted (merged) into the current heap; objects not
   * present in the snapshot are left untouched. Callers hydrate object
   * by object, so clearing the heap here would destroy earlier restores.
   *
   * Fails closed on malformed input: no partial object is inserted from
   * an unparseable entry.
   */

  const u8 *d = buffer_ref(snapshot, 0);
  u64 len = buffer_length(snapshot);

  u64 pos = json_skip_ws(d, len, 0);
  if (pos >= len || d[pos] != '{')
    return AK_E_JSON_INVALID;

  spin_lock(&heap_lock);

  s64 result = 0;
  boolean found = false;
  u64 vs = 0, ve = 0;

  if (!json_object_find(d, len, pos, "objects", 7, &found, NULL, &vs, &ve,
                        NULL, NULL)) {
    spin_unlock(&heap_lock);
    return AK_E_JSON_INVALID;
  }

  if (found) {
    /* Full snapshot: iterate the "objects" array */
    u64 p = json_skip_ws(d, ve, vs);
    if (p >= ve || d[p] != '[') {
      spin_unlock(&heap_lock);
      return AK_E_JSON_INVALID;
    }
    p++;
    p = json_skip_ws(d, ve, p);
    if (!(p < ve && d[p] == ']')) {
      while (p < ve) {
        p = json_skip_ws(d, ve, p);
        u64 obj_start = p;
        if (p >= ve || d[p] != '{' || !json_skip_value(d, ve, &p)) {
          result = AK_E_JSON_INVALID;
          break;
        }
        s64 r = restore_object_json(d, p, obj_start);
        if (r != 0) {
          result = r;
          break;
        }
        p = json_skip_ws(d, ve, p);
        if (p < ve && d[p] == ',') {
          p++;
          continue;
        }
        if (p < ve && d[p] == ']')
          break;
        result = AK_E_JSON_INVALID;
        break;
      }
    }

    /* Optional "next_ptr": never move the generator backwards */
    if (result == 0 &&
        json_object_find(d, len, pos, "next_ptr", 8, &found, NULL, &vs, &ve,
                         NULL, NULL) &&
        found) {
      u64 np = 0;
      if (parse_u64_range(d, vs, ve, &np) && np > ak_heap_state.next_ptr)
        ak_heap_state.next_ptr = np;
    }
  } else {
    /* Single serialized object */
    result = restore_object_json(d, len, pos);
  }

  spin_unlock(&heap_lock);
  return result;
}

/*
 * Write unsigned integer to buffer as decimal string.
 * Helper for canonical JSON serialization.
 */
static void serialize_write_u64(buffer out, u64 val) {
  if (val == 0) {
    buffer_write(out, "0", 1);
    return;
  }

  char tmp[24];
  int len = 0;
  while (val > 0) {
    tmp[len++] = '0' + (val % 10);
    val /= 10;
  }

  /* Reverse into output */
  for (int i = len - 1; i >= 0; i--)
    buffer_write(out, &tmp[i], 1);
}

/*
 * Escape and write JSON string value with surrounding quotes.
 * Handles all JSON escape sequences per RFC 8259.
 * Control characters (0x00-0x1F) are escaped as \uXXXX.
 * Used by the JSON patch engine for object keys added via "add".
 */
static void serialize_write_json_string(buffer out, const char *str, u64 len) {
  static const char hex_digits[] = "0123456789abcdef";

  buffer_write(out, "\"", 1);

  for (u64 i = 0; i < len; i++) {
    unsigned char c = (unsigned char)str[i];
    switch (c) {
    case '"':
      buffer_write(out, "\\\"", 2);
      break;
    case '\\':
      buffer_write(out, "\\\\", 2);
      break;
    case '\b':
      buffer_write(out, "\\b", 2);
      break;
    case '\f':
      buffer_write(out, "\\f", 2);
      break;
    case '\n':
      buffer_write(out, "\\n", 2);
      break;
    case '\r':
      buffer_write(out, "\\r", 2);
      break;
    case '\t':
      buffer_write(out, "\\t", 2);
      break;
    default:
      if (c < 0x20) {
        /* Control character - escape as \u00XX */
        char escape[6] = {'\\',
                          'u',
                          '0',
                          '0',
                          hex_digits[(c >> 4) & 0x0F],
                          hex_digits[c & 0x0F]};
        buffer_write(out, escape, 6);
      } else {
        buffer_write(out, (char *)&c, 1);
      }
      break;
    }
  }

  buffer_write(out, "\"", 1);
}

/*
 * Write hex-encoded byte array as JSON string.
 * Used for owner_run_id and other binary fields.
 */
static void serialize_write_hex_string(buffer out, const u8 *data, u64 len) {
  static const char hex_digits[] = "0123456789abcdef";

  buffer_write(out, "\"", 1);

  for (u64 i = 0; i < len; i++) {
    char hex[2];
    hex[0] = hex_digits[(data[i] >> 4) & 0x0F];
    hex[1] = hex_digits[data[i] & 0x0F];
    buffer_write(out, hex, 2);
  }

  buffer_write(out, "\"", 1);
}

/*
 * Get taint level name for serialization.
 * Returns canonical string representation.
 */
static const char *taint_to_string(ak_taint_t taint) {
  switch (taint) {
  case AK_TAINT_TRUSTED:
    return "trusted";
  case AK_TAINT_SANITIZED_URL:
    return "sanitized_url";
  case AK_TAINT_SANITIZED_PATH:
    return "sanitized_path";
  case AK_TAINT_SANITIZED_SQL:
    return "sanitized_sql";
  case AK_TAINT_SANITIZED_CMD:
    return "sanitized_cmd";
  case AK_TAINT_SANITIZED_HTML:
    return "sanitized_html";
  case AK_TAINT_UNTRUSTED:
    return "untrusted";
  default:
    return "unknown";
  }
}

/*
 * Calculate string length.
 */
static u64 str_len(const char *s) {
  u64 len = 0;
  while (s[len])
    len++;
  return len;
}

static buffer serialize_object_internal(heap h, ak_heap_object_t *obj) {
  /*
   * Serialize a single heap object to canonical JSON format.
   *
   * Output format (canonical - keys in fixed order, no whitespace):
   * {
   *   "ptr": <u64>,
   *   "type_hash": <u64>,
   *   "version": <u64>,
   *   "created_ms": <u64>,
   *   "modified_ms": <u64>,
   *   "taint": "<string>",
   *   "deleted": <boolean>,
   *   "owner_run_id": "<hex-string>",
   *   "value": <embedded-json>
   * }
   *
   * Properties:
   *   - Deterministic: same object always produces same output
   *   - Canonical: keys in fixed order for consistent hashing
   *   - Complete: includes all object metadata and value
   *
   * Used for:
   *   - State snapshots (crash recovery)
   *   - Audit logging (INV-4 compliance)
   *   - State sync between VMs
   *
   * Caller must hold heap_lock (or otherwise own obj).
   */

  /* Estimate buffer size:
   * - Fixed overhead for keys/formatting: ~200 bytes
   * - owner_run_id hex: 32 bytes
   * - Numbers (max 20 digits each * 5): ~100 bytes
   * - Taint string: ~20 bytes
   * - Value: variable
   */
  u64 value_len = obj->value ? buffer_length(obj->value) : 4; /* "null" */
  u64 initial_size = 400 + value_len;

  buffer result = allocate_buffer(h, initial_size);
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  /* Start object */
  buffer_write(result, "{", 1);

  /* "ptr":<u64> - canonical key order starts with ptr */
  buffer_write(result, "\"ptr\":", 6);
  serialize_write_u64(result, obj->ptr);

  /* "type_hash":<u64> */
  buffer_write(result, ",\"type_hash\":", 13);
  serialize_write_u64(result, obj->type_hash);

  /* "version":<u64> */
  buffer_write(result, ",\"version\":", 11);
  serialize_write_u64(result, obj->version);

  /* "created_ms":<u64> */
  buffer_write(result, ",\"created_ms\":", 14);
  serialize_write_u64(result, obj->created_ms);

  /* "modified_ms":<u64> */
  buffer_write(result, ",\"modified_ms\":", 15);
  serialize_write_u64(result, obj->modified_ms);

  /* "taint":"<string>" */
  buffer_write(result, ",\"taint\":\"", 10);
  const char *taint_str = taint_to_string(obj->taint);
  buffer_write(result, taint_str, str_len(taint_str));
  buffer_write(result, "\"", 1);

  /* "deleted":<boolean> */
  buffer_write(result, ",\"deleted\":", 11);
  if (obj->deleted) {
    buffer_write(result, "true", 4);
  } else {
    buffer_write(result, "false", 5);
  }

  /* "owner_run_id":"<hex-string>" */
  buffer_write(result, ",\"owner_run_id\":", 16);
  serialize_write_hex_string(result, obj->owner_run_id, AK_TOKEN_ID_SIZE);

  /* "value":<embedded-json> or null */
  buffer_write(result, ",\"value\":", 9);
  if (obj->value && buffer_length(obj->value) > 0) {
    /* Value is already JSON - embed directly for canonical output.
     * The value is stored as valid JSON, so we can include it as-is.
     * This preserves the exact stored representation for hashing. */
    buffer_write(result, buffer_ref(obj->value, 0), buffer_length(obj->value));
  } else {
    buffer_write(result, "null", 4);
  }

  /* Close object */
  buffer_write(result, "}", 1);

  return result;
}

buffer ak_heap_serialize_object(heap h, u64 ptr) {
  if (!ak_heap_state.initialized)
    return NULL;

  spin_lock(&heap_lock);
  ak_heap_object_t *obj = find_object(ptr);
  buffer result = obj ? serialize_object_internal(h, obj) : NULL;
  spin_unlock(&heap_lock);

  return result;
}

/* ============================================================
 * TRANSACTION SUPPORT
 * ============================================================ */

ak_heap_txn_t *ak_heap_txn_begin(void) {
  if (!ak_heap_state.initialized)
    return NULL;

  ak_heap_txn_t *txn = allocate(ak_heap_state.h, sizeof(ak_heap_txn_t));
  if (!txn)
    return NULL;

  txn->ops = NULL;
  txn->ops_tail = NULL;
  txn->op_count = 0;
  txn->active = true;

  return txn;
}

static void txn_add_op(ak_heap_txn_t *txn, ak_txn_op_t *op) {
  op->next = NULL;
  if (txn->ops_tail) {
    txn->ops_tail->next = op;
    txn->ops_tail = op;
  } else {
    txn->ops = op;
    txn->ops_tail = op;
  }
  txn->op_count++;
}

u64 ak_heap_txn_alloc(ak_heap_txn_t *txn, u64 type_hash, buffer value,
                      u8 *run_id, ak_taint_t taint) {
  if (!txn || !txn->active)
    return 0;

  ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
  if (!op)
    return 0;

  op->op_type = TXN_OP_ALLOC;
  op->type_hash = type_hash;
  op->taint = taint;

  /* Clone value */
  u64 len = buffer_length(value);
  op->value = allocate_buffer(ak_heap_state.h, len);
  if (op->value)
    buffer_write(op->value, buffer_ref(value, 0), len);

  if (run_id)
    runtime_memcpy(op->run_id, run_id, AK_TOKEN_ID_SIZE);
  else
    runtime_memset(op->run_id, 0, AK_TOKEN_ID_SIZE);

  /* Assign provisional pointer */
  op->ptr = ak_heap_state.next_ptr + txn->op_count;

  txn_add_op(txn, op);

  return op->ptr;
}

s64 ak_heap_txn_write(ak_heap_txn_t *txn, u64 ptr, buffer patch,
                      u64 expected_version) {
  if (!txn || !txn->active)
    return -EINVAL;

  ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
  if (!op)
    return -ENOMEM;

  op->op_type = TXN_OP_WRITE;
  op->ptr = ptr;
  op->expected_version = expected_version;

  /* Clone patch */
  u64 len = buffer_length(patch);
  op->value = allocate_buffer(ak_heap_state.h, len);
  if (op->value)
    buffer_write(op->value, buffer_ref(patch, 0), len);

  txn_add_op(txn, op);

  return 0;
}

s64 ak_heap_txn_delete(ak_heap_txn_t *txn, u64 ptr, u64 expected_version) {
  if (!txn || !txn->active)
    return -EINVAL;

  ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
  if (!op)
    return -ENOMEM;

  op->op_type = TXN_OP_DELETE;
  op->ptr = ptr;
  op->expected_version = expected_version;
  op->value = NULL;

  txn_add_op(txn, op);

  return 0;
}

s64 ak_heap_txn_commit(ak_heap_txn_t *txn) {
  if (!txn || !txn->active)
    return -EINVAL;

  /*
   * BATCH semantics: All or nothing
   *
   * Phase 1: Validate all operations
   * Phase 2: Apply all operations
   */

  /* Phase 1: Validation */
  ak_txn_op_t *op = txn->ops;
  while (op) {
    switch (op->op_type) {
    case TXN_OP_ALLOC:
      /* Validate schema */
      if (!ak_heap_validate_schema(op->type_hash, op->value)) {
        txn->active = false;
        return AK_E_SCHEMA_INVALID;
      }
      break;

    case TXN_OP_WRITE: {
      ak_heap_object_t *obj = find_object(op->ptr);
      if (!obj || obj->deleted) {
        txn->active = false;
        return -ENOENT;
      }
      if (obj->version != op->expected_version) {
        txn->active = false;
        return AK_E_CONFLICT;
      }
      break;
    }

    case TXN_OP_DELETE: {
      ak_heap_object_t *obj = find_object(op->ptr);
      if (!obj || obj->deleted) {
        txn->active = false;
        return -ENOENT;
      }
      if (obj->version != op->expected_version) {
        txn->active = false;
        return AK_E_CONFLICT;
      }
      break;
    }
    }
    op = op->next;
  }

  /* Phase 2: Apply */
  op = txn->ops;
  while (op) {
    switch (op->op_type) {
    case TXN_OP_ALLOC:
      ak_heap_alloc(op->type_hash, op->value, op->run_id, op->taint);
      break;

    case TXN_OP_WRITE:
      ak_heap_write(op->ptr, op->value, op->expected_version, NULL);
      break;

    case TXN_OP_DELETE:
      ak_heap_delete(op->ptr, op->expected_version);
      break;
    }
    op = op->next;
  }

  txn->active = false;
  return 0;
}

/*
 * FIX(BUG-009): Document ownership semantics.
 *
 * WARNING: This function FREES the transaction structure.
 * After calling ak_heap_txn_rollback(), the txn pointer becomes INVALID.
 * Caller MUST NOT use the txn pointer after this call returns.
 *
 * Ownership model:
 *   - ak_heap_txn_begin() allocates and returns ownership to caller
 *   - ak_heap_txn_commit() keeps txn allocated (caller must call rollback to
 * free)
 *   - ak_heap_txn_rollback() transfers ownership back and frees
 *
 * Correct usage:
 *   ak_heap_txn_t *txn = ak_heap_txn_begin();
 *   // ... do operations ...
 *   if (error) {
 *       ak_heap_txn_rollback(txn);
 *       txn = NULL;  // CRITICAL: Clear pointer after rollback
 *       return;
 *   }
 *   ak_heap_txn_commit(txn);
 *   ak_heap_txn_rollback(txn);  // Always call to free resources
 *   txn = NULL;
 */
void ak_heap_txn_rollback(ak_heap_txn_t *txn) {
  if (!txn)
    return;

  /* Free all buffered operations */
  ak_txn_op_t *op = txn->ops;
  while (op) {
    ak_txn_op_t *next = op->next;
    if (op->value)
      deallocate_buffer(op->value);
    deallocate(ak_heap_state.h, op, sizeof(ak_txn_op_t));
    op = next;
  }

  txn->ops = NULL;
  txn->ops_tail = NULL;
  txn->op_count = 0;
  txn->active = false;

  deallocate(ak_heap_state.h, txn, sizeof(ak_heap_txn_t));
}
