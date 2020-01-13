#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef memcpy
#define memcpy(dst, src, n) __builtin_memcpy((dst), (src), (n))
#endif

// struct nat_table {
//     int i_ifindex;
//     int e_ifindex;
//     unsigned char eth[ETH_ALEN];
//     __be32 addr;
//     __u16 sport;
// };

// struct bpf_map_def SEC("maps") nat_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(__be32),
//     .value_size  = sizeof(struct nat_table),
//     .max_entries = 100,
// };

#define AF_INET 2

static __always_inline int ip_checksum(struct iphdr *iph) {
    __u32 check = (__u32) iph->check;
    check += (__u32) bpf_htons(0x0100);
    iph->check = (__sum16)(check + (check >= 0xffff));
    // return --iph->ttl;
    return 0;
}

SEC("prog")
int xdp_ext_nat(struct xdp_md *ctx) {
    void *data         = (void *) (long) ctx->data;
    void *data_end     = (void *) (long) ctx->data_end;
    __u32 ifindex      = ctx->ingress_ifindex;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u64 nh_off;
    __u16 h_proto;

    // bpf_printk("ifindex(%d)\n", ifindex);

    // return XDP_PASS;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        goto err;
    }

    struct bpf_fib_lookup fib = {};

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        iph = data + nh_off;

        if (iph + 1 > (struct iphdr *) data_end) {
            goto err;
        }

        if (iph->ttl <= 1) {
            goto err;
        }

        fib.family      = AF_INET;
        fib.tos         = iph->tos;
        fib.l4_protocol = iph->protocol;
        fib.sport       = 0;
        fib.dport       = 0;
        fib.tot_len     = bpf_ntohs(iph->tot_len);
        fib.ipv4_src    = iph->saddr;
        fib.ipv4_dst    = iph->daddr;
    } else {
        goto out;
    }

    fib.ifindex = ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            if (h_proto == bpf_htons(ETH_P_IP)) {
                ip_checksum(iph);
            }
            memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib.smac, ETH_ALEN);

            bpf_printk("lookup success if(%d)\n", fib.ifindex);
            break;
        default:
            bpf_printk("lookup failed if(%d)\n", fib.ifindex);
            goto err;
    }

    goto out;
err:
    return XDP_ABORTED;
out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
