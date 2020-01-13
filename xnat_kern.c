#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "bpf_helpers.h"
#include "stats.h"

// #define SEC(NAME) __attribute__((section(NAME), used))

#include "printk.h"

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#ifndef memcpy
#define memcpy(dst, src, n) __builtin_memcpy((dst), (src), (n))
#endif

struct nat_table {
    int ifindex;
    unsigned char eth[ETH_ALEN];
    __be32 addr;
    __u16 sport;
    __u16 dport;
};

struct bpf_map_def SEC("maps") stats_map = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct datarec),
    .max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") tx_port = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = ETH_ALEN,
    .value_size  = ETH_ALEN,
    .max_entries = 100,
};

struct bpf_map_def SEC("maps") nat_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__be32),
    .value_size  = sizeof(struct nat_table),
    .max_entries = 100,
};

static __aligned_inline void swap_src_dst_mac(struct ethhdr *eth) {
    unsigned char temp[ETH_ALEN];

    memcpy(temp, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, temp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *hdr) {
    __be32 temp = hdr->saddr;
    hdr->saddr  = hdr->daddr;
    hdr->daddr  = hdr->saddr;
}

static __always_inline __u32 stats(struct xdp_md *ctx, __u32 action) {

    void *data_end = (void *) (long) ctx->data_end;
    void *data     = (void *) (long) ctx->data;

    if (action >= XDP_ACTION_MAX) {
        return XDP_ABORTED;
    }

    struct datarec *rec = bpf_map_lookup_elem(&stats_map, &action);

    if (!rec) {
        return XDP_ABORTED;
    }

    __u64 bytes = data_end - data;

    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return action;
}

SEC("prog")
int xdp_nat(struct xdp_md *ctx) {

    void *data                = (void *) (long) ctx->data;
    void *data_end            = (void *) (long) ctx->data_end;
    struct bpf_fib_lookup fib = {};
    struct ethhdr *eth        = data;
    struct iphdr *iph;
    __u16 h_proto;
    __u64 nh_off;
    int rc;
    int action;
    struct nat_table *nat;
    __be32 addr = 0;

    action = XDP_PASS;

    nf_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto out;
    }

    h_proto = eth->h_proto;
    if (h_proto == bpf_htnos(ETH_P_IP)) {
        iph = data + nh_off;

        if (iph + 1 > data_end) {
            action = XDP_DROP;
            goto out;
        }

        addr = iph->daddr;
    }

    nat = bpf_map_lookup_elem(&nat_map, &addr);
    if (!nat) {
        goto out;
    }

    memctp(eth->);
    // h_proto = eth->h_proto;
    // if (h_proto == bpf_htnos(ETH_P_IP)) {
    //     iph = data + nh_off;

    //     if (iph + 1 > data_end) {
    //         action = XDP_DROP;
    //         goto out;
    //     }

    //     fib.family      = AF_INET;
    //     fib.tos         = iph->tos;
    //     fib.l4_protocol = iph->protocol;
    //     fib.sport       = 0;
    //     fib.dport       = 0;
    //     fib.tot_len     = ntohs(iph->tot_len);
    //     fib.ipv4_src    = iph->saddr;
    //     fib.ipv4_dst    = iph->daddr;
    // }

    // fib.ifindex = ctx->ingress_ifindex;

    // // rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);
    // rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

    goto out;
err:
    action = XDP_ABORTED;
out:
    return stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
