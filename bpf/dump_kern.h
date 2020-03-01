#ifndef __PCAP_H
#define __PCAP_H

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "egress.h"
#include "ingress.h"

#define MAX_CPUS 128
#define SAMPLE_SIZE 1024ul

#define min(x, y) ((x) < (y) ? (x) : (y))

struct S {
    __u16 cookie;
    __u16 pkt_ken;
} __attribute__((packed));

struct bpf_map_def SEC("maps") pcap_map = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

static __always_inline int
dump(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data     = (void *) (long) ctx->data;

    if (data < data_end) {
        __u64 flags = BPF_F_CURRENT_CPU;
        __u16 size;
        int ret;
        struct S metadata;

        metadata.cookie  = 0xdead;
        metadata.pkt_ken = (__u16)(data_end - data);

        size = min(metadata.pkt_ken, SAMPLE_SIZE);

        flags |= (__u64) size << 32;

        ret = bpf_perf_event_output(
            ctx, &pcap_map, flags, &metadata, sizeof(metadata));

        if (ret) {
            bpf_printk("perf_event_output failed: %d\n", ret);
        }
    }

    return 0;
}
SEC("xnat/dump/ingress") int xdp_ingress_dump(struct xdp_md *ctx) {
    bpf_printk("SEC: xnat/dump/ingress\n");

    dump(ctx);

    bpf_tail_call(ctx, &ingress_prog_array, 1);

    return XDP_ABORTED;
}

SEC("xnat/dump/egress") int xdp_egress_dump(struct xdp_md *ctx) {

    bpf_printk("SEC: xnat/dump/egress\n");

    dump(ctx);

    bpf_tail_call(ctx, &egress_prog_array, 1);

    return XDP_ABORTED;
}
#endif /* end of include guard */
