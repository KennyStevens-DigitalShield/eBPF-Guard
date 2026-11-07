# BPF-Guard

A lightweight eBPF-based detector for evasive eBPF rootkits on Linux.

Three detection layers, run on a 5-second cycle, plus one real-time tracker:

1. **BPF load/attach tracking** — hooks `sys_enter_bpf`, reports every process
   that loads or attaches a BPF program, with its binary path resolved from
   `/proc/<pid>/exe` (not just the spoofable process name).
2. **Cross-view detection** — compares the kernel's own process and BPF
   program lists (read via `iter/task` and `iter/bpf_prog`, which bypass
   `getdents64`/`bpf()` entirely) against what `/proc` and `bpf_prog_get_next_id`
   report. A mismatch held across two consecutive scans means something is
   hidden from the normal view.
3. **Helper-usage scanning** — disassembles every loaded program looking for
   calls to `bpf_probe_write_user`, `bpf_override_return`, and
   `bpf_send_signal`: the primitives rootkits use to rewrite memory, force
   return values, or send signals. (Originally implemented as kprobes on
   those helpers directly; see "What didn't work" below for why that
   failed.)
4. **XDP/TC network check** — flags any BPF program attached at the XDP or
   TC layer on any interface, the delivery mechanism for BPF-based network
   backdoors (e.g. Boopkit-style C2).

## Build

```bash
sudo apt install clang llvm libelf-dev zlib1g-dev libbpf-dev bpftool \
  gcc make linux-headers-$(uname -r)

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c guard.bpf.c -o guard.bpf.o
bpftool gen skeleton guard.bpf.o > guard.skel.h
gcc -O2 -Wall guard.c -o guard -lbpf -lelf -lz
```

`vmlinux.h` is kernel/machine-specific — regenerate it on every target, never
copy it between machines.

## Run

```bash
sudo ./guard
```

For persistence, install as a systemd service (see `bpf-guard.service`):

```bash
sudo cp bpf-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bpf-guard.service
journalctl -u bpf-guard.service -f
```

## What to expect on a clean system

Alerts are not inherently bad — `BPF_LOAD/ATTACH` will fire for systemd and
any legitimate software using BPF (VPN split-tunneling, container runtimes,
observability agents, etc). Build a baseline for your system: check every
`exe=` path against a known package (`dpkg -S <path>`, `dpkg -V <package>`)
the first time you see it. `[HIDDEN PID]`, `[HIDDEN BPF PROG]`, and
`[HELPER-USE]` alerts deserve closer attention regardless of source.

## Testing

Each detection layer was validated against a real positive, not just "runs
without error." See `NOTES.md` for the full story, including dead ends.
Summary:

| Layer | Test | Tool |
|---|---|---|
| Helper-usage scan | Load a program calling `bpf_send_signal` | `signal_test.c` (included) |
| XDP/TC check | Attach a no-op XDP program to `lo` | `xdp_pass.c` (included) |
| Cross-view (hidden PID) | Hide a real PID from `/proc` | [bad-bpf](https://github.com/pathtofile/bad-bpf)'s `pidhide`, run in an isolated VM |

```bash
# helper-usage scan test
clang -O2 -target bpf -c signal_test.c -o signal_test.o
sudo bpftool prog load signal_test.o /sys/fs/bpf/signal_test
# expect: [HELPER-USE] ... uses bpf_send_signal
sudo rm /sys/fs/bpf/signal_test

# xdp/tc check test
clang -O2 -target bpf -c xdp_pass.c -o xdp_pass.o
sudo ip link set dev lo xdpgeneric obj xdp_pass.o sec xdp
# expect: [NET-BPF PROG] and [NET-BPF ATTACHED]
sudo ip link set dev lo xdpgeneric off
```

**Do not run `pidhide` or any other rootkit PoC on a production machine.**
Use a disposable, snapshotted VM.

## Known limitations

- Every check except the raw BPF program disassembly ultimately asks the
  kernel through `bpf()` or `/proc`. A sufficiently advanced rootkit that
  successfully hooks those syscalls could, in principle, interfere with
  parts of this tool too. The cross-view layer is the most resistant to this
  since it reads kernel structures directly via iterators, but it is not
  immune to an attacker who specifically targets the iterator path.
- Does not detect kernel-module rootkits that bypass BPF entirely.
- Does not detect non-BPF network backdoors.
- The original design used kprobes directly on `bpf_probe_write_user`,
  `bpf_override_return`, and `bpf_send_signal` as tripwires. On kernels with
  lockdown enabled (common with Secure Boot), `bpf_probe_write_user` is
  unusable by any BPF program — which is good for security but means it
  can't be hooked either. The other two failed to attach as kprobes for
  unrelated reasons. The helper-usage scanner (layer 3 above) replaces this
  approach entirely.

## License

MIT — see `LICENSE`.
