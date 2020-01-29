#ifndef __PCAP_H
#define __PCAP_H

#include <linux/bpf.h>

#include "bpf_helpers.h"

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
pcap(struct xdp_md *ctx) {
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


// TODO tail_callで切り替えられるようにする
SEC("pcap")
int
xnat_pcap(struct xdp_md *ctx) {
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

    return XDP_PASS;
}

#endif /* end of include guard */
