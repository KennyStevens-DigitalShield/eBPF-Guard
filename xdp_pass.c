#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp") int pass(struct xdp_md *c) { return XDP_PASS; }
char LICENSE[] SEC("license") = "GPL";
