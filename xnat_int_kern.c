#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "stats_kern.h"
#include "common.h"
#include "parser.h"
#include "define_kern.h"
#include "nat_kern.h"

#include "printk.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

struct bpf_map_def SEC("maps") tx_map = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
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

struct bpf_map_def SEC("maps") port_pool_map = {
    // .type        = BPF_MAP_TYPE_PERCPU_HASH,
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u16),
    .value_size  = sizeof(__u16),
    .max_entries = 60000,
};

struct bpf_map_def SEC("maps") freelist_map = {
    .type        = BPF_MAP_TYPE_STACK,
    .key_size    = 0,
    .value_size  = sizeof(__u16),
    .max_entries = 60000,
    .map_flags   = 0,
};

static __always_inline __u16 get_icmp_id(struct hdr_cursor *nh,
                                         void *data_end) {

    __u16 id       = 0;
    __u16 sequence = 0;

    struct icmphdr *icmphdr = nh->pos;

    if (icmphdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    id       = bpf_ntohs(icmphdr->un.echo.id);
    sequence = bpf_ntohs(icmphdr->un.echo.sequence);

    bpf_printk("icmp id(%d) sequence(%d)\n", id, sequence);

    return id;
}

SEC("prog")
int xdp_nat(struct xdp_md *ctx) {

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct ethhdr *eth = data;
    __u64 nh_off;
    __u16 h_proto;
    int action = XDP_PASS;

    struct hdr_cursor nh;

    __u32 ifindex = ctx->ingress_ifindex;
    __u64 flags   = 0;

    unsigned char *dst;
    unsigned char *src;

    nh.pos = data;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        goto err;
    }

    h_proto = eth->h_proto;

    switch (bpf_htons(h_proto)) {
        case ETH_P_ARP:
            bpf_printk("ETH_P_ARP\n");
            break;
        case ETH_P_IP:
            bpf_printk("ETH_P_IP\n");

            struct iphdr *iph;
            __u16 port_pool_key = 0;
            iph                 = data + nh_off;

            if (iph + 1 > (struct iphdr *) data_end) {
                goto err;
            }
            nh.pos = iph + 1;

            // TODO プロトコル判別してポート書き換える

            switch (iph->protocol) {
                case IPPROTO_ICMP:
                    bpf_printk("IPPROTO_ICMP\n");
                    port_pool_key = get_icmp_id(&nh, data_end);
                    break;
                case IPPROTO_UDP:
                    bpf_printk("IPPROTO_UDP\n");
                    break;
                case IPPROTO_TCP:
                    bpf_printk("IPPROTO_TCP\n");
                    break;
            }

            iph->saddr = bpf_htonl(0xc0a80101);
            iph->daddr = bpf_htonl(0xc0a80102);

            __u16 *find_port;
            find_port = bpf_map_lookup_elem(&port_pool_map, &port_pool_key);

            if (!find_port) {
                bpf_printk("find port failed\n");
            } else {
                __u16 free_port = 0;
                if (*find_port == 0) {
                    int err = 0;

                    err = bpf_map_pop_elem(&freelist_map, &free_port);
                    if (err) {
                        bpf_printk("bpf_map_pop_elem failed\n");
                    } else {
                        bpf_map_update_elem(
                            &port_pool_map, &port_pool_key, &free_port, 0);
                        bpf_printk("Update port (%ld) -> (%ld)\n",
                                   port_pool_key,
                                   free_port);
                    }
                } else {
                    bpf_printk("Exist port (%ld) -> (%ld)\n",
                               port_pool_key,
                               *find_port);
                }
            }

            ip_checksum(iph);

            dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
            if (!dst) {
                goto err;
            }

            memcpy(eth->h_dest, dst, ETH_ALEN);

            src = bpf_map_lookup_elem(&redirect_params, eth->h_dest);
            if (!src) {
                goto err;
            }

            memcpy(eth->h_source, src, ETH_ALEN);

            action = bpf_redirect_map(&tx_map, ifindex, flags);

            goto out;
        default:
            bpf_printk("Default\n");
            goto err;
    }

    goto out;
err:
    action = XDP_ABORTED;
out:
    return stats(ctx, &stats_map, action);
}

char _license[] SEC("license") = "GPL";
