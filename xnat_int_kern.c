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
#include "nat_kern.h"
#include "xnat_int_map.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

#define MAX_ICMP_LEN 1500

static __always_inline __be16 get_icmp_id(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmphdr **icmphdr) {

    __be16 id       = 0;
    __be16 sequence = 0;

    struct icmphdr *hdr = nh->pos;

    if (hdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    id       = hdr->un.echo.id;
    sequence = hdr->un.echo.sequence;

    bpf_printk("DEBUG: icmp id(%d) sequence(%d)\n",
               bpf_ntohs(id),
               bpf_ntohs(sequence));

    *icmphdr = nh->pos;

    return id;
}

static __always_inline __be16 update_icmp_id(struct icmphdr *hdr,
                                             __be16 new_port) {
    hdr->un.echo.id = new_port;

    return 0;
}

static __always_inline __u32 update_icmp_checksum(struct icmphdr *old_hdr,
                                                  struct icmphdr *new_hdr) {

    __sum16 old_csum;

    old_csum          = old_hdr->checksum;
    old_hdr->checksum = 0;
    new_hdr->checksum = 0;

    new_hdr->checksum =
        generic_checksum(new_hdr, old_hdr, sizeof(struct icmphdr), old_csum);

    return 0;
}

static __always_inline __u32 update_ipv4_checksum(struct iphdr *old,
                                                  struct iphdr *new) {
    __sum16 old_csum;

    old_csum   = old->check;
    old->check = 0;
    new->check = 0;

    new->check = generic_checksum(new, old, sizeof(struct iphdr), old_csum);
    return 0;
}

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

static __always_inline __u32 update_icmp(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct nat_table *nt) {
    struct icmphdr *icmphdr;
    struct icmphdr old_icmphdr;

    icmphdr = nh->pos;

    if (icmphdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    old_icmphdr = *icmphdr;

    nt->proto    = IPPROTO_ICMP;
    nt->sport    = get_icmp_id(nh, data_end, &icmphdr);
    nt->dport    = 0;
    nt->new_port = get_new_port(nt->sport);

    if (nt->new_port > 0) {
        update_icmp_id(icmphdr, nt->new_port);

        update_icmp_checksum(&old_icmphdr, icmphdr);

        bpf_printk("DEBUG: type(%d) code(%d) checksum(0x%x)\n",
                   icmphdr->type,
                   icmphdr->code,
                   icmphdr->checksum);
        bpf_printk("DEBUG: id(%d) sequence(%d)\n",
                   bpf_ntohs(icmphdr->un.echo.id),
                   bpf_ntohs(icmphdr->un.echo.sequence));
    } else {
        return -1;
    }
    return 0;
}

static __always_inline __u32 update_ipv4(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct nat_table *nt) {
    struct iphdr *iph;
    struct iphdr old_iphdr;

    iph = nh->pos;

    if (iph + 1 > (struct iphdr *) data_end) {
        return -1;
    }
    nh->pos = iph + 1;

    // TODO プロトコル判別してポート書き換える
    switch (iph->protocol) {
        case IPPROTO_ICMP:
            if (update_icmp(nh, data_end, nt) < 0) {
                bpf_printk("ERR: update_icmp\n");
                return -1;
            }
            break;
        case IPPROTO_UDP:
            // bpf_printk("IPPROTO_UDP\n");
            nt->proto = IPPROTO_UDP;
            break;
        case IPPROTO_TCP:
            // bpf_printk("IPPROTO_TCP\n");
            nt->proto = IPPROTO_TCP;
            break;
    }

    old_iphdr = *iph;

    nt->saddr = iph->saddr;
    nt->daddr = iph->daddr;

    iph->saddr = bpf_htonl(0xc0a80101);
    iph->daddr = bpf_htonl(0xc0a80102);

    nt->new_addr = iph->saddr;

    update_ipv4_checksum(&old_iphdr, iph);

    return 0;
}

static __always_inline __u32 update_eth(struct ethhdr *eth,
                                        struct nat_table *nt) {
    unsigned char *dst;
    unsigned char *src;

    memcpy(nt->seth, eth->h_source, ETH_ALEN);
    memcpy(nt->deth, eth->h_dest, ETH_ALEN);

    dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
    if (!dst) {
        bpf_printk("ERR: lookup source mac failed\n");
        return -1;
    }

    memcpy(eth->h_dest, dst, ETH_ALEN);

    src = bpf_map_lookup_elem(&redirect_params, eth->h_dest);
    if (!src) {
        bpf_printk("ERR: lookup dest mac failed\n");
        return -1;
    }

    memcpy(eth->h_source, src, ETH_ALEN);

    return 0;
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

// static __always_inline __u32 arp_request() {
// }

static __always_inline __u32 proxy_arp(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct ethhdr *eth,
                                       __u32 ingress_ifindex) {

    int action = XDP_PASS;

    struct ether_arp *arphdr = nh->pos;
    bpf_printk("hdr len %d\n", data_end - nh->pos);
    bpf_printk("arphdr len %d\n", sizeof(struct arphdr));
    bpf_printk("ether_arp len %d\n", sizeof(struct ether_arp));
    bpf_printk("__be32 len %d\n", sizeof(__be32));

    bpf_printk("data_end %p\n", data_end);
    bpf_printk("pos1 %p\n", (struct arphdr *) (nh->pos + 1));
    bpf_printk("pos2 %p\n", (struct ether_arp *) (arphdr + 1));

    if (arphdr + 1 > (struct ether_arp *) data_end) {
        return -1;
    }
    // TODO arp header書き換える

    arphdr->ar_hrd = bpf_htons(ARPHRD_ETHER);
    arphdr->ar_pro = bpf_htons(0x0800);
    arphdr->ar_hln = ETH_ALEN;
    arphdr->ar_pln = 4;
    arphdr->ar_op  = bpf_htons(ARPOP_REQUEST);

    __u32 *egress_ifindex;

    egress_ifindex = bpf_map_lookup_elem(&tx_map, &ingress_ifindex);
    if (!egress_ifindex) {
        bpf_printk("ERR: lookup egress ifindex failed\n");
        return -1;
    }

    bpf_printk("egress_ifindex(%d)\n", *egress_ifindex);

    struct ifinfo *info;
    info = bpf_map_lookup_elem(&if_map, egress_ifindex);
    if (!info) {
        bpf_printk("ERR: lookup source mac failed\n");
        return -1;
    }

    memcpy(arphdr->ar_sha, info->mac, ETH_ALEN);
    memcpy(arphdr->ar_sip, &info->ip, sizeof(info->ip));

    memset(arphdr->ar_tha, 0x00, ETH_ALEN);

    bpf_printk("\n");
    bpf_printk("==== arp header ====\n");
    bpf_printk("\thardware address(0x%x)\n", arphdr->ar_hrd);
    bpf_printk("\tprotocol address(0x%x)\n", bpf_ntohs(arphdr->ar_pro));
    bpf_printk("\tlengeth of hardware address(%d)\n", arphdr->ar_hln);
    bpf_printk("\tlengeth of protocol address(%d)\n", arphdr->ar_pln);
    bpf_printk("\topcode(0x%x)\n", arphdr->ar_op);

    bpf_printk("\tsender ha(%x:%x:%x)\n",
               arphdr->ar_sha[0],
               arphdr->ar_sha[1],
               arphdr->ar_sha[2]);
    bpf_printk("\tsender ha(%x:%x:%x)\n",
               arphdr->ar_sha[3],
               arphdr->ar_sha[4],
               arphdr->ar_sha[5]);

    bpf_printk("\tsender ip(%d.%d)\n", arphdr->ar_sip[0], arphdr->ar_sip[1]);
    bpf_printk("\tsender ip(.%d.%d)\n", arphdr->ar_sip[2], arphdr->ar_sip[3]);

    bpf_printk("\ttarget ha(%x:%x:%x)\n",
               arphdr->ar_tha[0],
               arphdr->ar_tha[1],
               arphdr->ar_tha[2]);
    bpf_printk("\ttarget ha(%x:%x:%x)\n",
               arphdr->ar_tha[3],
               arphdr->ar_tha[4],
               arphdr->ar_tha[5]);

    bpf_printk("\ttarget ip(%d.%d)\n", arphdr->ar_tip[0], arphdr->ar_tip[1]);
    bpf_printk("\ttarget ip(.%d.%d)\n", arphdr->ar_tip[2], arphdr->ar_tip[3]);

    memcpy(eth->h_source, info->mac, ETH_ALEN);
    memset(eth->h_dest, 0xff, ETH_ALEN);

    bpf_printk("src mac(%x:%x:%x:)\n",
               eth->h_source[0],
               eth->h_source[1],
               eth->h_source[2]);
    bpf_printk("src mac(%x:%x:%x)\n",
               eth->h_source[3],
               eth->h_source[4],
               eth->h_source[5]);
    bpf_printk(
        "dst mac(%x:%x:%x:)\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_printk(
        "dst mac(%x:%x:%x)\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    action = bpf_redirect_map(&tx_map, ingress_ifindex, 0);

    bpf_printk("action(%d)\n", action);

    return action;
}

static __always_inline __u32 update_nat_map(struct nat_table *nt,
                                            struct nm_k *key) {

    int err = -1;
    err     = bpf_map_update_elem(&nat_map, key, nt, BPF_NOEXIST);
    if (err < 0) {
        return -1;
    }
    return err;
}

SEC("prog")
int xdp_nat(struct xdp_md *ctx) {

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
