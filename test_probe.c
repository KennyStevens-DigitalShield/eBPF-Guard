// probe_test.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe/vfs_read")
int test_probe(struct pt_regs *ctx)
{
    char buf[4] = {0};
    bpf_probe_write_user((void *)0, buf, 1);   /* will fail at runtime, that's fine — we're testing detection, not the write */
    return 0;
}
