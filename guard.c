#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include "guard.skel.h"


static volatile sig_atomic_t stop;
static void on_sig(int sig) { (void)sig; stop = 1; }

/* Show libbpf warnings/errors so load or attach failures say why */
static int libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl > LIBBPF_WARN) return 0;
    return vfprintf(stderr, fmt, ap);
}

/* ---------------- ring buffer alerts from the kernel side ---------------- */
static const char *names[] = {
    "?", "BPF_LOAD/ATTACH", "probe_write_user", "override_return", "send_signal"
};

static int on_event(void *ctx, void *data, size_t n)
{
    struct event { unsigned type, pid, arg; char comm[16]; } *e = data;

    if ((pid_t)e->pid == getpid()) return 0;   /* skip guard's own BPF activity */

    const char *nm = e->type < 5 ? names[e->type] : "unknown";

    char exe[256] = "(exited)";
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/%u/exe", e->pid);
    ssize_t len = readlink(linkpath, exe, sizeof(exe) - 1);
    if (len > 0) exe[len] = '\0';

    printf("[ALERT] %-18s pid=%u comm=%.16s exe=%s arg=%u\n", nm, e->pid, e->comm, exe, e->arg);
    fflush(stdout);
    return 0;
}

/* ---------------- helpers ---------------- */
static unsigned *slurp(int link_fd, size_t *n)
{
    int fd = bpf_iter_create(link_fd);
    if (fd < 0) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    ssize_t r;
    if (!buf) { close(fd); return NULL; }
    while ((r = read(fd, buf + len, cap - len)) > 0) {
        len += r;
        if (len == cap) {
            char *nb = realloc(buf, cap *= 2);
            if (!nb) { free(buf); close(fd); return NULL; }
            buf = nb;
        }
    }
    close(fd);
    *n = len / sizeof(unsigned);
    return (unsigned *)buf;
}

static int has(const unsigned *a, size_t n, unsigned v)
{
    for (size_t i = 0; i < n; i++) if (a[i] == v) return 1;
    return 0;
}

static size_t proc_pids(unsigned *out, size_t max)
{
    size_t n = 0;
    DIR *d = opendir("/proc");
    struct dirent *de;
    while (d && (de = readdir(d)) && n < max) {
        unsigned p = (unsigned)atoi(de->d_name);
        if (p) out[n++] = p;
    }
    if (d) closedir(d);
    return n;
}

static size_t syscall_prog_ids(unsigned *out, size_t max)
{
    size_t n = 0;
    __u32 id = 0;
    while (!bpf_prog_get_next_id(id, &id) && n < max) out[n++] = id;
    return n;
}

/* ---------------- cross-view: kernel iterators vs syscall/proc view ---------------- */
#define MAXMISS 256
struct missset { unsigned id[MAXMISS]; size_t n; };

/* Alert only if an ID is missing from the userspace view on two scans in a
 * row. This filters races from processes/programs that start or exit mid-scan. */
static void report_hidden(const char *label, const char *via,
                          const unsigned *kernel, size_t kn,
                          const unsigned *visible, size_t vn,
                          struct missset *prev)
{
    struct missset cur = { .n = 0 };
    for (size_t i = 0; i < kn; i++) {
        unsigned id = kernel[i];
        if (has(visible, vn, id)) continue;
        if (cur.n < MAXMISS) cur.id[cur.n++] = id;
        if (has(prev->id, prev->n, id))
            printf("[HIDDEN %s] id=%u in kernel, not via %s\n", label, id, via);
    }
    *prev = cur;
}

static void crossview(struct guard_bpf *s)
{
    static struct missset miss_pid, miss_prog;
    static unsigned *vis, *ids;
    size_t kn = 0, pn = 0;

    if (!vis) {
        vis = malloc((1 << 20) * sizeof(unsigned));
        ids = malloc((1 << 20) * sizeof(unsigned));
        if (!vis || !ids) { fprintf(stderr, "out of memory\n"); exit(1); }
    }

    unsigned *k = slurp(bpf_link__fd(s->links.dump_task), &kn);
    if (k) {
        size_t un = proc_pids(vis, 1 << 20);
        report_hidden("PID", "/proc", k, kn, vis, un, &miss_pid);
        free(k);
    }

    unsigned *kp = slurp(bpf_link__fd(s->links.dump_prog), &pn);
    if (kp) {
        size_t un = syscall_prog_ids(ids, 1 << 20);
        report_hidden("BPF PROG", "bpf()", kp, pn, ids, un, &miss_prog);
        free(kp);
    }
    fflush(stdout);
}

/* ---------------- XDP/TC check ---------------- */
#define MAX_SEEN 1024
static unsigned long long seen_net[MAX_SEEN];
static size_t seen_net_n;

static int net_seen(unsigned long long key)
{
    for (size_t i = 0; i < seen_net_n; i++) if (seen_net[i] == key) return 1;
    if (seen_net_n < MAX_SEEN) seen_net[seen_net_n++] = key;
    return 0;
}

static const char *net_type_name(__u32 t)
{
    switch (t) {
    case BPF_PROG_TYPE_XDP:       return "XDP";
    case BPF_PROG_TYPE_SCHED_CLS: return "TC/SCHED_CLS";
    case BPF_PROG_TYPE_SCHED_ACT: return "TC/SCHED_ACT";
    default:                      return NULL;
    }
}

static void scan_net_progs(void)
{
    __u32 id = 0;
    while (!bpf_prog_get_next_id(id, &id)) {
        int fd = bpf_prog_get_fd_by_id(id);
        if (fd < 0) continue;
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);
        if (!bpf_obj_get_info_by_fd(fd, &info, &len)) {
            const char *t = net_type_name(info.type);
            if (t && !net_seen((unsigned long long)id))
                printf("[NET-BPF PROG] id=%u type=%s name=%.16s\n", id, t, info.name);
        }
        close(fd);
    }
}

static void report_attached(unsigned ifindex, const char *ifname,
                            int hook_no, const char *hook, __u32 prog_id)
{
    if (!prog_id) return;
    unsigned long long key = (1ULL << 63) | ((unsigned long long)ifindex << 40) |
                             ((unsigned long long)hook_no << 32) | prog_id;
    if (!net_seen(key))
        printf("[NET-BPF ATTACHED] if=%s hook=%s prog_id=%u\n", ifname, hook, prog_id);
}

static void scan_net_attach(void)
{
    struct if_nameindex *ifs = if_nameindex();
    if (!ifs) return;

    static const struct { enum bpf_attach_type t; const char *n; } tcx[] = {
        { BPF_TCX_INGRESS, "tcx-ingress" },
        { BPF_TCX_EGRESS,  "tcx-egress"  },
    };

    for (struct if_nameindex *i = ifs; i->if_index; i++) {
        LIBBPF_OPTS(bpf_xdp_query_opts, xo);
        if (!bpf_xdp_query(i->if_index, 0, &xo)) {
            report_attached(i->if_index, i->if_name, 1, "xdp-generic", xo.skb_prog_id);
            report_attached(i->if_index, i->if_name, 2, "xdp-native",  xo.drv_prog_id);
            report_attached(i->if_index, i->if_name, 3, "xdp-offload", xo.hw_prog_id);
        }

        for (int k = 0; k < 2; k++) {
            __u32 ids[32] = {};
            LIBBPF_OPTS(bpf_prog_query_opts, qo);
            qo.prog_ids = ids;
            qo.prog_cnt = 32;
            if (!bpf_prog_query_opts(i->if_index, tcx[k].t, &qo))
                for (__u32 j = 0; j < qo.prog_cnt && j < 32; j++)
                    report_attached(i->if_index, i->if_name, 4 + k, tcx[k].n, ids[j]);
        }
    }
    if_freenameindex(ifs);
}

static void check_net(void)
{
    scan_net_progs();
    scan_net_attach();
    fflush(stdout);
}

/* ---------------- helper-usage scan (tripwire replacement) ---------------- */
#define MAX_HELPER_SEEN 512
static unsigned helper_seen[MAX_HELPER_SEEN];
static size_t helper_seen_n;

static int helper_prog_seen(unsigned id)
{
    for (size_t i = 0; i < helper_seen_n; i++) if (helper_seen[i] == id) return 1;
    if (helper_seen_n < MAX_HELPER_SEEN) helper_seen[helper_seen_n++] = id;
    return 0;
}

/* BPF_CALL opcode: class=BPF_JMP(0x05), op=BPF_CALL(0x80) -> 0x85.
 * src_reg==0 means a helper call (imm = helper id), not a call to another BPF prog. */
static void scan_prog_for_helpers(__u32 prog_id)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "bpftool prog dump xlated id %u 2>/dev/null", prog_id);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    char line[512];
    char progname[64] = "(unknown)";
    while (fgets(line, sizeof(line), fp)) {
        char *introt = strstr(line, "int ");
        char *paren  = introt ? strchr(introt, '(') : NULL;
        if (introt && paren && paren > introt + 4) {
            size_t len = (size_t)(paren - (introt + 4));
            if (len >= sizeof(progname)) len = sizeof(progname) - 1;
            memcpy(progname, introt + 4, len);
            progname[len] = 0;
        }

        const char *h = NULL;
        if (strstr(line, "call bpf_probe_write_user")) h = "bpf_probe_write_user";
        else if (strstr(line, "call bpf_override_return")) h = "bpf_override_return";
        else if (strstr(line, "call bpf_send_signal"))      h = "bpf_send_signal";
        if (h && !helper_prog_seen(prog_id))
            printf("[HELPER-USE] prog_id=%u name=%s uses %s\n", prog_id, progname, h);
    }
    pclose(fp);
}

static void scan_all_progs_for_helpers(void)
{
    __u32 id = 0;
    while (!bpf_prog_get_next_id(id, &id))
        scan_prog_for_helpers(id);
}

/* ---------------- main ---------------- */
int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    libbpf_set_print(libbpf_log);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    struct guard_bpf *s = guard_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "load failed (need root, kernel >= 5.10 with BTF)\n");
        return 1;
    }

    /* Tripwires are best-effort: attach them individually so one failure doesn't kill the guard */
    bpf_program__set_autoattach(s->progs.t_write_user, false);
    bpf_program__set_autoattach(s->progs.t_override,   false);
    bpf_program__set_autoattach(s->progs.t_signal,     false);

    if (guard_bpf__attach(s)) {      /* core: sys_enter_bpf tracepoint + the two iterators */
        fprintf(stderr, "core attach failed: see libbpf message above\n");
        guard_bpf__destroy(s);
        return 1;
    }

    s->links.t_write_user = bpf_program__attach(s->progs.t_write_user);
    if (!s->links.t_write_user) fprintf(stderr, "WARN: tripwire bpf_probe_write_user unavailable\n");
    s->links.t_override = bpf_program__attach(s->progs.t_override);
    if (!s->links.t_override) fprintf(stderr, "WARN: tripwire bpf_override_return unavailable\n");
    s->links.t_signal = bpf_program__attach(s->progs.t_signal);
    if (!s->links.t_signal) fprintf(stderr, "WARN: tripwire bpf_send_signal unavailable\n");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.rb), on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring buffer setup failed\n");
        guard_bpf__destroy(s);
        return 1;
    }

    printf("guard running. Ctrl-C to stop.\n");
    for (int tick = 0; !stop; tick++) {
        ring_buffer__poll(rb, 1000);
        if (tick % 5 == 0) {
            crossview(s);
            check_net();
            scan_all_progs_for_helpers();
        }
    }

    ring_buffer__free(rb);
    guard_bpf__destroy(s);
    return 0;
}
