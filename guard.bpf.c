#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

enum { EV_BPF_CMD = 1, EV_WRITE_USER, EV_OVERRIDE, EV_SIGNAL };

struct event { __u32 type, pid, arg; char comm[16]; };

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 16); } rb SEC(".maps");

/* dedupe noisy tripwires per tgid */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 4096);
         __type(key, __u64); __type(value, __u8); } seen SEC(".maps");

static __always_inline void emit(__u32 type, __u32 arg, bool dedupe)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (dedupe) {
        __u64 k = ((__u64)type << 32) | tgid; __u8 one = 1;
        if (bpf_map_lookup_elem(&seen, &k)) return;
        bpf_map_update_elem(&seen, &k, &one, BPF_ANY);
    }
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;
    e->type = type; e->pid = tgid; e->arg = arg;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* 1. Anyone loading/attaching BPF: PROG_LOAD=5 PROG_ATTACH=8 RAW_TP_OPEN=17 LINK_CREATE=28 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int on_bpf(struct trace_event_raw_sys_enter *ctx)
{
    int cmd = ctx->args[0];
    if (cmd == 5 || cmd == 8 || cmd == 17 || cmd == 28)
        emit(EV_BPF_CMD, cmd, false);
    return 0;
}

/* 2. Tripwires: called from *victim* context, so comm/pid show who is being tampered with */
SEC("kprobe/bpf_probe_write_user")
int BPF_KPROBE(t_write_user) { emit(EV_WRITE_USER, 0, true); return 0; }

SEC("kprobe/bpf_override_return")
int BPF_KPROBE(t_override) { emit(EV_OVERRIDE, 0, true); return 0; }

SEC("kprobe/bpf_send_signal")
int BPF_KPROBE(t_signal) { emit(EV_SIGNAL, 0, true); return 0; }

/* 3. Ground-truth enumerators (bypass syscall hooks) */
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct task_struct *t = ctx->task;
    if (!t || t->tgid != t->pid) return 0;
    __u32 pid = t->tgid;
    bpf_seq_write(ctx->meta->seq, &pid, sizeof(pid));
    return 0;
}

SEC("iter/bpf_prog")
int dump_prog(struct bpf_iter__bpf_prog *ctx)
{
    struct bpf_prog *p = ctx->prog;
    if (!p) return 0;
    __u32 id = p->aux->id;
    bpf_seq_write(ctx->meta->seq, &id, sizeof(id));
    return 0;
}
