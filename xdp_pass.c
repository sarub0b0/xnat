#include <linux/bpf.h>
#include "bpf_helpers.h"

#include "stats_kern.h"
#include "printk.h"

SEC("pass")
int xdp_pass(struct xdp_md *ctx) {

    bpf_printk("pass\n");

    return stats(ctx, &stats_map, XDP_PASS);
}

SEC("drop")
int xdp_drop(struct xdp_md *ctx) {

    bpf_printk("drop\n");

    return stats(ctx, &stats_map, XDP_DROP);
}
char _license[] SEC("license") = "GPL";
