#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <errno.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "common.h"
#include "printk.h"
#include "define_kern.h"
#include "stats_kern.h"
#include "parser.h"
#include "ifinfo.h"
#include "nat.h"
#include "eth.h"
#include "icmp.h"
#include "ipv4.h"

// #define PROG(F) SEC(#F) int bpf_func_##F

// enum {
//     ARP = 1,
//     IP,
//     IPV6,
// };

// struct bpf_map_def SEC("maps") prog_map = {
//     .type        = BPF_MAP_TYPE_PROG_ARRAY,
//     .key_size    = sizeof(__u32),
//     .value_size  = sizeof(__u32),
//     .max_entries = 8,
// };

struct bpf_map_def SEC("maps") tx_map = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 50,
};

struct bpf_map_def SEC("maps") redirect_params = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = ETH_ALEN,
    .value_size  = ETH_ALEN,
    .max_entries = 50,
};

struct bpf_map_def SEC("maps") nat_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct nm_k),
    .value_size  = sizeof(struct nat_table),
    .max_entries = 100,
};

struct bpf_map_def SEC("maps") if_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct ifinfo),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") port_pool_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__be16),
    .value_size  = sizeof(__be16),
    .max_entries = 65536,
};

struct bpf_map_def SEC("maps") freelist_map = {
    .type        = BPF_MAP_TYPE_STACK,
    .key_size    = 0,
    .value_size  = sizeof(__be16),
    .max_entries = 60000,
    .map_flags   = 0,
};

static __always_inline __be16 get_new_port(__be16 port_pool_key) {
    int err;
    __be16 *find_port;
    __be16 free_port = 0;

    find_port = bpf_map_lookup_elem(&port_pool_map, &port_pool_key);

    if (!find_port) {
        bpf_printk("ERR: find port failed\n");
    } else {
        if (*find_port == 0) {

            err = bpf_map_pop_elem(&freelist_map, &free_port);
            if (err) {
                bpf_printk("ERR: bpf_map_pop_elem failed\n");
            } else {
                bpf_map_update_elem(
                    &port_pool_map, &port_pool_key, &free_port, 0);
                bpf_printk("INFO: Update port (%ld) -> (%ld)\n",
                           bpf_ntohs(port_pool_key),
                           bpf_ntohs(free_port));
            }
        } else {
            bpf_printk("INFO: Exist port (%ld) -> (%ld)\n",
                       bpf_ntohs(port_pool_key),
                       bpf_ntohs(*find_port));
        }
        free_port = *find_port;
    }

    return free_port;
}

// static __always_inline void err_map_update(int err, int flags) {
//     bpf_printk("ERR: ");
//     switch (err) {
//         case E2BIG:
//             bpf_printk("the map reached the max entries limit");
//             break;
//         case EEXIST:
//             bpf_printk("the element with key already exists in the map");
//             break;
//         case ENOENT:
//             bpf_printk("the element with key doesn't exist in the map");
//             break;
//     }
//     switch (flags) {
//         case BPF_ANY:
//             bpf_printk(" flags(BPF_ANY)\n");
//             break;
//         case BPF_EXIST:
//             bpf_printk(" flags(BPF_EXIST)\n");
//             break;
//         case BPF_NOEXIST:
//             bpf_printk(" flags(BPF_NOEXIST)\n");
//             break;
//     }
// }

static __always_inline __u32 update_nat_map(struct nat_table *nt,
                                            struct nm_k *key) {
    return bpf_map_update_elem(&nat_map, key, nt, BPF_NOEXIST);
}

SEC("xnat/ingress")
int xnat_ingress(struct xdp_md *ctx) {

    struct nat_table nt = {0};

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct hdr_cursor nh;

    __u32 ifindex;

    int err;

    int action = XDP_PASS;
    int flags  = 0;

    nh.pos  = data;
    ifindex = ctx->ingress_ifindex;

    struct ethhdr *eth;
    __be16 h_proto;
    h_proto = parse_ethhdr(&nh, data_end, &eth);

    if (eth + 1 > (struct ethhdr *) data_end) {
        goto err;
    }

    if (h_proto < 0) {
        bpf_printk("ERR: Invalid h_proto(%d)\n", h_proto);
        goto err;
    }

    bpf_printk("INFO: eth proto=0x%x\n", bpf_ntohs(h_proto));

    switch (bpf_ntohs(h_proto)) {
        case ETH_P_ARP:
            bpf_printk("ETH_P_ARP\n");
            // if (proxy_arp(&nh, data_end, eth, ifindex) == XDP_REDIRECT) {
            //     goto out;
            // }
            // bpf_printk("ERR: proxy arp failed\n");
            goto out;
        case ETH_P_IP:
            bpf_printk("ETH_P_IP\n");
            if (update_ipv4(&nh, data_end, &nt) < 0) {
                bpf_printk("ERR: update_ipv4 failed\n");
                goto err;
            }
            break;
        default:
            bpf_printk("Default\n");
            goto out;
    }

    bpf_printk("update_eth\n");
    if (update_eth(eth, &nt) < 0) {
        bpf_printk("ERR: update_eth failed\n");
        goto err;
    }
    __u32 *egress_ifindex;

    egress_ifindex = bpf_map_lookup_elem(&tx_map, &ifindex);
    if (!egress_ifindex) {
        bpf_printk("ERR: lookup egress ifindex failed\n");
        goto err;
    } else {
        nt.egress_ifindex = *egress_ifindex;
    }
    nt.ingress_ifindex = ifindex;

    struct nm_k key;
    key.addr = nt.saddr;
    key.port = nt.new_port;

    bpf_printk("\n");
    bpf_printk("==== nat table ====\n");
    bpf_printk(
        "\taddr=0x%x port=%d\n", bpf_ntohl(key.addr), bpf_ntohs(key.port));
    bpf_printk("\tingress_ifindex (%d)\n", nt.ingress_ifindex);
    bpf_printk("\tegress_ifindex(%d)\n", nt.egress_ifindex);
    bpf_printk("\tsrc addr(0x%x)\n", bpf_ntohl(nt.saddr));
    bpf_printk("\tdst addr(0x%x)\n", bpf_ntohl(nt.daddr));
    bpf_printk("\tsrc port(%d)\n", bpf_ntohs(nt.sport));
    bpf_printk("\tdst port(%d)\n", bpf_ntohs(nt.dport));
    bpf_printk("\tproto(0x%x)\n", nt.proto);
    bpf_printk("\tnew addr(0x%x)\n", bpf_ntohl(nt.new_addr));
    bpf_printk("\tnew port(%d)\n", bpf_ntohs(nt.new_port));

    bpf_printk("\n");

    err = update_nat_map(&nt, &key);
    if (err) {
        bpf_printk("ERR: Exist nat table. key addr(0x%x) port(%d)\n",
                   bpf_ntohl(key.addr),
                   bpf_ntohs(key.port));
        // goto err;
    }

    action = bpf_redirect_map(&tx_map, ifindex, flags);

    goto out;
err:
    action = XDP_ABORTED;
out:
    return stats(ctx, &stats_map, action);
    // return action;
}

SEC("xnat/egress")
int xnat_egress(struct xdp_md *ctx) {
    struct nat_table nt = {0};

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct hdr_cursor nh;

    __u32 egress_ifindex;

    int err;

    int action = XDP_PASS;
    int flags  = 0;

    nh.pos = data;

    egress_ifindex = ctx->ingress_ifindex;

    struct ethhdr *eth;
    __be16 h_proto;
    h_proto = parse_ethhdr(&nh, data_end, &eth);

    if (eth + 1 > (struct ethhdr *) data_end) {
        goto err;
    }

    if (h_proto < 0) {
        bpf_printk("ERR: Invalid h_proto(%d)\n", h_proto);
        goto err;
    }

    bpf_printk("INFO: eth proto=0x%x\n", bpf_ntohs(h_proto));

    switch (bpf_ntohs(h_proto)) {
        case ETH_P_ARP:
            bpf_printk("ETH_P_ARP: XDP_PASS\n");
            goto out;
        case ETH_P_IP:
            bpf_printk("ETH_P_IP\n");
            if (update_ipv4(&nh, data_end, &nt) < 0) {
                bpf_printk("ERR: update_ipv4 failed\n");
                goto err;
            }
            break;
        default:
            bpf_printk("Default\n");
            goto out;
    }

    bpf_printk("update_eth\n");
    if (update_eth(eth, &nt) < 0) {
        bpf_printk("ERR: update_eth failed\n");
        goto err;
    }
    __u32 *ingress_ifindex;

    ingress_ifindex = bpf_map_lookup_elem(&tx_map, &egress_ifindex);
    if (!ingress_ifindex) {
        bpf_printk("ERR: lookup egress ifindex failed\n");
        goto err;
    }
    action = bpf_redirect_map(&tx_map, egress_ifindex, flags);

    goto out;
err:
    action = XDP_ABORTED;
out:
    // return action;

    return stats(ctx, &stats_map, action);
}

// PROG(ARP)(struct xdp_md *ctx) {
//     bpf_printk("bpf_tail_call ARP\n");

//     return XDP_PASS;
// }

// PROG(IP)(struct xdp_md *ctx) {
//     bpf_printk("bpf_tail_call IP\n");
//     return XDP_PASS;
// }
// PROG(IPV6)(struct xdp_md *ctx) {
//     bpf_printk("bpf_tail_call IPV6\n");
//     return XDP_PASS;
// }

char _license[] SEC("license") = "GPL";
