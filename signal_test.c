// signal_test.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe/vfs_read")
int test_signal(struct pt_regs *ctx)
{
    bpf_send_signal(0);   /* signal 0: validity check only, doesn't actually kill anything */
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
