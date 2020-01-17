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
// #include "eth.h"
// #include "icmp.h"
// #include "ipv4.h"
// #include "fib.h"

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
//
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
    .value_size  = sizeof(struct nat_info),
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

static __always_inline void _print_fib(struct bpf_fib_lookup *fib) {
    bpf_printk("\n");
    bpf_printk("==== fib info ====\n");
    bpf_printk("family(%d)\n", fib->family);
    bpf_printk("tos 0x%x)\n", fib->tos);
    bpf_printk("protocol(0x%x)\n", fib->l4_protocol);
    bpf_printk("tot_len(0x%x)\n", fib->tot_len);
    bpf_printk("src(0x%x)\n", bpf_ntohl(fib->ipv4_src));
    bpf_printk("dst(0x%x)\n", bpf_ntohl(fib->ipv4_dst));
    bpf_printk("sport(0x%x)\n", fib->sport);
    bpf_printk("dport(0x%x)\n", fib->dport);
    bpf_printk("smac(%x:%x:%x:)\n", fib->smac[0], fib->smac[1], fib->smac[2]);
    bpf_printk("smac(%x:%x:%x:)\n", fib->smac[3], fib->smac[4], fib->smac[5]);
    bpf_printk("dmac(%x:%x:%x:)\n", fib->dmac[0], fib->dmac[1], fib->dmac[2]);
    bpf_printk("dmac(%x:%x:%x:)\n", fib->dmac[3], fib->dmac[4], fib->dmac[5]);
    bpf_printk("ifindex(%d)\n", fib->ifindex);

    bpf_printk("\n");
}

static __always_inline void _print_net_info(struct nm_k *key,
                                            struct nat_info *nat) {
    bpf_printk("\n");
    bpf_printk("==== nat table ====\n");
    bpf_printk(
        "\taddr=0x%x port=%d\n", bpf_ntohl(key->addr), bpf_ntohs(key->port));
    bpf_printk("\tingress_ifindex (%d)\n", nat->ingress_ifindex);
    bpf_printk("\tegress_ifindex(%d)\n", nat->egress_ifindex);
    bpf_printk("\tsrc addr(0x%x)\n", bpf_ntohl(nat->saddr));
    bpf_printk("\tdst addr(0x%x)\n", bpf_ntohl(nat->daddr));
    bpf_printk("\tsrc port(%d)\n", bpf_ntohs(nat->sport));
    bpf_printk("\tdst port(%d)\n", bpf_ntohs(nat->dport));
    bpf_printk("\tproto(0x%x)\n", nat->proto);
    bpf_printk("\tnew addr(0x%x)\n", bpf_ntohl(nat->new_addr));
    bpf_printk("\tnew port(%d)\n", bpf_ntohs(nat->new_port));

    bpf_printk("\n");
}

static __always_inline void set_fib(struct iphdr *iph,
                                    struct bpf_fib_lookup *fib) {

    fib->family      = AF_INET;
    fib->tos         = iph->tos;
    fib->l4_protocol = iph->protocol;
    fib->sport       = 0;
    fib->dport       = 0;
    fib->tot_len     = bpf_ntohs(iph->tot_len);
    fib->ipv4_src    = iph->saddr;
    fib->ipv4_dst    = iph->daddr;
}

static __always_inline int fib_lookup(struct xdp_md *ctx,
                                      struct bpf_fib_lookup *fib) {
    int rc;
    rc = bpf_fib_lookup(ctx, fib, sizeof(*fib), BPF_FIB_LOOKUP_OUTPUT);

    bpf_printk("bpf_fib_lookup return code(%d)\n", rc);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            return XDP_REDIRECT;
        case BPF_FIB_LKUP_RET_BLACKHOLE:
            bpf_printk("BPF_FIB_LKUP_RET_BLACKHOLE\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_UNREACHABLE:
            return XDP_DROP;
            bpf_printk("BPF_FIB_LKUP_RET_UNREACHABLE\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_PROHIBIT:
            bpf_printk("BPF_FIB_LKUP_RET_PROHIBIT\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
            bpf_printk("BPF_FIB_LKUP_RET_NOT_FWDED\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
            bpf_printk("BPF_FIB_LKUP_RET_FWD_DISABLED\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
            bpf_printk("BPF_FIB_LKUP_RET_UNSUPP_LWT\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_NO_NEIGH:
            bpf_printk("BPF_FIB_LKUP_RET_NO_NEIGH\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            bpf_printk("BPF_FIB_LKUP_RET_FRAG_NEEDED\n");
            // pass
            return XDP_PASS;
    }
    return rc;
}

static __always_inline int update_eth(struct ethhdr *eth,
                                      struct nat_info *nat) {
    unsigned char *dst;
    unsigned char *src;

    memcpy(nat->seth, eth->h_source, ETH_ALEN);
    memcpy(nat->deth, eth->h_dest, ETH_ALEN);

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
static __always_inline int update_ipv4_checksum(struct iphdr *old,
                                                struct iphdr *new) {
    __sum16 old_csum;

    old_csum   = old->check;
    old->check = 0;
    new->check = 0;

    new->check = generic_checksum(new, old, sizeof(struct iphdr), old_csum);
    return 0;
}

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

static __always_inline int update_icmp_checksum(struct icmphdr *old_hdr,
                                                struct icmphdr *new_hdr) {

    __sum16 old_csum;

    old_csum          = old_hdr->checksum;
    old_hdr->checksum = 0;
    new_hdr->checksum = 0;

    new_hdr->checksum =
        generic_checksum(new_hdr, old_hdr, sizeof(struct icmphdr), old_csum);

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
static __always_inline int update_icmp(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct nat_info *nat) {
    struct icmphdr *icmphdr;
    struct icmphdr old_icmphdr;

    icmphdr = nh->pos;

    if (icmphdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    old_icmphdr = *icmphdr;

    nat->proto    = IPPROTO_ICMP;
    nat->sport    = get_icmp_id(nh, data_end, &icmphdr);
    nat->dport    = 0;
    nat->new_port = get_new_port(nat->sport);

    if (nat->new_port > 0) {
        update_icmp_id(icmphdr, nat->new_port);

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

static __always_inline int update_ipv4(struct iphdr *iph,
                                       __u32 ifindex,
                                       struct nat_info *nat) {
    struct iphdr old_iphdr;
    struct ifinfo *info;

    old_iphdr = *iph;

    nat->saddr = iph->saddr;
    nat->daddr = iph->daddr;

    info = bpf_map_lookup_elem(&if_map, &ifindex);
    if (!info) {
        return -1;
    }

    nat->new_addr = info->ip;
    iph->saddr    = info->ip;

    update_ipv4_checksum(&old_iphdr, iph);

    return 0;
}

static __always_inline int update_l4(struct hdr_cursor *nh,
                                     void *data_end,
                                     __u8 l4_protocol,
                                     struct nat_info *nat) {

    switch (l4_protocol) {
        case IPPROTO_ICMP:
            if (update_icmp(nh, data_end, nat) < 0) {
                return -1;
            }
            break;
        case IPPROTO_UDP:
            break;
        case IPPROTO_TCP:
            break;
    }
    return 0;
}

static __always_inline int next_hop_lookup(struct xdp_md *ctx,
                                           struct bpf_fib_lookup *fib) {

    return fib_lookup(ctx, fib);
}

static __always_inline int update_nat_map(struct nat_info *nat,
                                          struct nm_k *key) {
    return bpf_map_update_elem(&nat_map, key, nat, BPF_NOEXIST);
}

SEC("xnat/ingress")
int xnat_ingress(struct xdp_md *ctx) {

    struct nat_info nat = {0};

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct hdr_cursor nh;

    __u32 ingress_ifindex;

    int err;

    int action = XDP_PASS;
    int flags  = 0;

    nh.pos              = data;
    ingress_ifindex     = ctx->ingress_ifindex;
    nat.ingress_ifindex = ingress_ifindex;

    __u32 *egress_ifindex;
    egress_ifindex = bpf_map_lookup_elem(&tx_map, &ingress_ifindex);
    if (!egress_ifindex) {
        bpf_printk("ERR: lookup egress ifindex failed\n");
        goto err;
    } else {
        nat.egress_ifindex = *egress_ifindex;
    }

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

    __u8 l4_protocol;
    struct iphdr *iph;
    struct bpf_fib_lookup fib = {};

    l4_protocol = 0;
    switch (bpf_ntohs(h_proto)) {
        case ETH_P_ARP:
            goto out;
        case ETH_P_IP:
            iph = nh.pos;
            if (iph + 1 > (struct iphdr *) data_end) goto err;
            nh.pos = iph + 1;

            l4_protocol = iph->protocol;

            fib.ifindex = *egress_ifindex;
            set_fib(iph, &fib);
            int rc = next_hop_lookup(ctx, &fib);
            if (rc != XDP_REDIRECT) {
                action = rc;
                goto out;
            }
            _print_fib(&fib);

            if (update_ipv4(iph, *egress_ifindex, &nat) < 0) {
                bpf_printk("ERR: update_ipv4 failed\n");
                goto err;
            }

            break;
        case ETH_P_IPV6:
            break;
        default:
            bpf_printk("Default\n");
            goto out;
    }

    if (update_l4(&nh, data_end, l4_protocol, &nat) < 0) {
        bpf_printk("ERR: update_l4 failed\n");
        goto err;
    }

    bpf_printk("update_eth\n");
    if (update_eth(eth, &nat) < 0) {
        bpf_printk("ERR: update_eth failed\n");
        goto err;
    }
    struct nm_k key;
    key.addr = nat.new_addr;
    key.port = nat.new_port;

    _print_net_info(&key, &nat);

    err = update_nat_map(&nat, &key);
    if (err) {
        bpf_printk("ERR: Exist nat table. key addr(0x%x) port(%d)\n",
                   bpf_ntohl(key.addr),
                   bpf_ntohs(key.port));
        // goto err;
    }

    action = bpf_redirect_map(&tx_map, ingress_ifindex, flags);

    goto out;
err:
    action = XDP_ABORTED;
out:
    return stats(ctx, &stats_map, action);
    // return action;
}

SEC("xnat/egress")
int xnat_egress(struct xdp_md *ctx) {
    int action = XDP_PASS;
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
