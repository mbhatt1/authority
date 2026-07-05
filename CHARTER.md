# Authority Charter

## Mission

Provide a unikernel that runs a single untrusted program per virtual machine and
enforces its security in the kernel — with cryptographic capabilities, a
tamper-evident audit log, hard resource budgets, and deny-by-default policy — so
that what the program can do is constrained by the kernel, not by the
application's own good behavior.

## Tenets (unless you know better ones)

1. **Enforced, not advised.** Security decisions happen inside the syscall path,
   before an effect executes. If a request is not provably authorized, it is
   denied.

2. **Minimalist.** Built on Nanos: one program per VM, no users, no shell, no
   ambient authority. Keep the kernel small and the attack surface smaller.

3. **Provable.** Every operation is recorded in an append-only, hash-chained
   audit log that is made durable before a response is returned, so the record
   cannot be silently rewritten.

4. **Honest.** Features are either enforced by the compiled kernel or they are
   not claimed. Failure modes fail closed.

## Contributions & Project Roles

All contributions must align with this charter.
