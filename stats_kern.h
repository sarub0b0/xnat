#ifndef __STATS_KERN_H
#define __STATS_KERN_H

#include "stats.h"
#include "define_kern.h"

struct bpf_map_def SEC("maps") stats_map = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct datarec),
    .max_entries = XDP_ACTION_MAX,
};

static __always_inline __u32 stats(struct xdp_md *ctx,
                                   struct bpf_map_def *map,
                                   __u32 action) {

    void *data_end = (void *) (long) ctx->data_end;
    void *data     = (void *) (long) ctx->data;

    if (action >= XDP_ACTION_MAX) {
        return XDP_ABORTED;
    }

    struct datarec *rec = bpf_map_lookup_elem(map, &action);

    if (!rec) {
        return XDP_ABORTED;
    }

    __u64 bytes = data_end - data;

    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return action;
}

#endif /* end of include guard */

