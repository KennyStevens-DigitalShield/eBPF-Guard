# Development notes

This tool went through substantial iteration. Keeping this here so the dead
ends are documented instead of silently disappearing — useful if you hit the
same walls.

## Design goal

Catch evasive eBPF rootkits without needing to hide anything to test it
(the testing methodology itself required care — see below).

## What didn't work: direct helper kprobes

Original design: kprobe directly on `bpf_probe_write_user`,
`bpf_override_return`, `bpf_send_signal`. All three failed to attach:

- `bpf_probe_write_user`: `Invalid argument`. Root cause (confirmed later
  via a load-time verifier test): kernel lockdown mode (`integrity` or
  stricter — commonly enabled alongside Secure Boot) disables this helper
  for *all* BPF program types at the verifier level. It's not that it
  can't be hooked; it can't be *called* by anything, which is a stronger
  protection than a kprobe tripwire would have given anyway.
- `bpf_override_return`: `No such file or directory`. Kernel built without
  `CONFIG_BPF_KPROBE_OVERRIDE`.
- `bpf_send_signal`: `Invalid argument`. BPF helpers generally aren't
  regular kallsyms-exported functions a kprobe can attach to cleanly; this
  is closer to the normal case than `bpf_probe_write_user`'s working
  (on non-locked-down kernels) being the exception.

Fix: made these tripwires best-effort (`bpf_program__set_autoattach(...,
false)`, then individually attach and log a warning on failure) so the
rest of the tool isn't blocked by their absence.

## What replaced it: helper-usage scanning

Instead of hooking the helper at the point of call, scan every *loaded*
program's instructions for calls to these helpers, on the same interval as
the other checks.

First attempt: read raw `xlated_prog_insns` via `bpf_obj_get_info_by_fd`,
decode `BPF_CALL` instructions, compare `imm` against `BPF_FUNC_*` constants.
This looked right but silently matched nothing. Root cause, found by dumping
raw instructions: the kernel rewrites `imm` in the xlated instruction stream
to an offset relative to `__bpf_call_base`, not the helper enum ID
(confirmed by comparing against `bpftool prog dump xlated`'s own resolved
output, e.g. `call bpf_trace_printk#-98208` — the `-98208` is exactly this
kind of offset, not a helper ID).

Fix: shell out to `bpftool prog dump xlated id <id>` and string-match on
`call bpf_<helper_name>` in its output, since bpftool already does the
kallsyms-based resolution correctly. Simpler and more correct than
reimplementing that resolution, at the cost of a subprocess spawn per
program per scan cycle.

## Testing methodology

A detector that's never produced a true positive is unverified, not proven.
Each layer was tested against something that actually exercises it:

- **XDP/TC check**: `xdp_pass.c`, a trivial `XDP_PASS` program, attached to
  `lo`. Confirmed `[NET-BPF PROG]` and `[NET-BPF ATTACHED]` both fire, and
  clear when detached.
- **Helper-usage scan**: `signal_test.c`, calling `bpf_send_signal(0)` from
  a kprobe on `vfs_read`. Loading alone (no attachment needed) triggers
  `[HELPER-USE]`. (`bpf_probe_write_user` can't be used for this test on a
  locked-down kernel — see above — so `bpf_send_signal` stood in.)
- **Cross-view / hidden PID**: this is the one layer specifically designed
  to survive a rootkit hooking `bpf()` or `/proc`, so testing it requires
  something that actually hides a process that way. Writing a
  PID-hiding tool, even for testing a defense, isn't something to build —
  it's a dual-use artifact regardless of stated intent. Instead, used
  [bad-bpf](https://github.com/pathtofile/bad-bpf)'s `pidhide`, a known,
  public, maintained PoC built for exactly this purpose, run inside an
  isolated, snapshotted VM (never on the host this tool is meant to
  protect). `sudo ./pidhide --pid-to-hide <pid>` against a disposable
  `sleep` process produced `[HIDDEN PID]` within one scan cycle, confirmed
  against `ls /proc/<pid>` independently failing at the same time.
  **Important finding**: `pidhide` itself failed to load on a
  lockdown-enabled kernel (same `bpf_probe_write_user` restriction as
  above) — it only loaded successfully on the VM, which didn't have the
  same lockdown configuration. Worth checking your own kernel's lockdown
  state (`cat /sys/kernel/security/lockdown`) before assuming this test
  will reproduce.

## Other things fixed along the way

- Build errors from a libbpf API mismatch (`bpf_prog_query_opts` doesn't
  take `target_ifindex` as a struct field; it's the function's first
  argument).
- A missing-link-wiring bug where a function was fully written and compiled
  but never actually called from the main loop — caught by adding debug
  logging rather than assuming silence meant success.
- Alert noise: excluded the guard's own PID from `BPF_LOAD/ATTACH` alerts,
  and added `/proc/<pid>/exe` resolution so alerts show a verifiable binary
  path instead of only the spoofable process `comm` name.
- `systemd` persistence: installed as a unit on `sysinit.target` (earlier
  than the default `multi-user.target`) so the guard starts as early in
  boot as practical.

## What this does NOT do

- Prevent anything. It's detect-only by design — see README limitations.
- Guarantee detection against a rootkit built specifically to evade *this*
  tool's known mechanisms (e.g., one that patches the iterator path itself,
  not just `/proc`/`bpf()`).
- Replace kernel hardening. Lockdown mode already blocked one entire class
  of attack here independent of anything this tool does — that's a
  reminder that detection and prevention are complementary, not
  substitutes for each other.
