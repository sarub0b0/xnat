
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
#include "define_kern.h"
#include "printk.h"
#include "checksum.h"
#include "stats_kern.h"
#include "parser.h"
#include "ifinfo.h"
#include "nat.h"
#include "pcapdump.h"

#include "ingress.h"
#include "egress.h"

#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *) 0)->MEMBER)

#define IP_CSUM_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define IP_DST_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, saddr))
#define IP_PROTO_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, protocol))
#define TCP_CSUM_OFF                                \
    (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
     offsetof(struct tcphdr, check))

#define UDP_CSUM_OFF                                \
    (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
     offsetof(struct udphdr, check))

#define TCP_DPORT_OFF                               \
    (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
     offsetof(struct tcphdr, dest))
#define IS_PSEUDO 0x10

#define PROG(F) SEC(#F) int bpf_func_##F

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

// bpf_printk用
static __always_inline __u64
ether_addr_to_u64(const __u8 *addr) {

    __u64 u = 0;

    for (int i = 0; i < ETH_ALEN; i++) {
        u = u << 8 | addr[i];
    }

    return u;
}

static __always_inline void
_print_iphdr(struct iphdr *h) {
    bpf_printk("\n");
    bpf_printk("==== ip header ==== \n");
    bpf_printk("  saddr(0x%x)\n", bpf_ntohl(h->saddr));
    bpf_printk("  daddr(0x%x)\n", bpf_ntohl(h->daddr));
    bpf_printk("  tos(0x%x)\n", h->tos);
    bpf_printk("  tot_len(%d)\n", bpf_ntohs(h->tot_len));
    bpf_printk("  id(%d)\n", bpf_ntohs(h->id));
    bpf_printk("  proto(%d)\n", h->protocol);
    bpf_printk("  ttl(%d)\n", h->ttl);
    bpf_printk("  frag_off(0x%x)\n", bpf_ntohs(h->frag_off));
    bpf_printk("  check(0x%x)\n", h->check);
    bpf_printk("\n");
}

static __always_inline void
_print_fib(struct bpf_fib_lookup *fib) {
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
    bpf_printk("smac(%llx)\n", ether_addr_to_u64(fib->smac));
    bpf_printk("dmac(%llx)\n", ether_addr_to_u64(fib->dmac));
    bpf_printk("ifindex(%d)\n", fib->ifindex);

    bpf_printk("\n");
}

static __always_inline void
_print_net_info(struct nm_k *key, struct nat_info *nat) {
    bpf_printk("\n");
    bpf_printk("==== nat table ====\n");
    bpf_printk(
        "\taddr=0x%x port=%d\n", bpf_ntohl(key->addr), bpf_ntohs(key->port));
    bpf_printk("\tingress_ifindex (%d)\n", nat->ingress_ifindex);
    bpf_printk("\tegress_ifindex(%d)\n", nat->egress_ifindex);
    bpf_printk("\tsrc mac(%llx)\n", ether_addr_to_u64(nat->seth));
    bpf_printk("\tdst mac(%llx)\n", ether_addr_to_u64(nat->deth));
    bpf_printk("\tsrc addr(0x%x)\n", bpf_ntohl(nat->saddr));
    bpf_printk("\tdst addr(0x%x)\n", bpf_ntohl(nat->daddr));
    bpf_printk("\tsrc port(%d)\n", bpf_ntohs(nat->sport));
    bpf_printk("\tdst port(%d)\n", bpf_ntohs(nat->dport));
    bpf_printk("\tproto(0x%x)\n", nat->proto);
    bpf_printk("\tnew addr(0x%x)\n", bpf_ntohl(nat->new_addr));
    bpf_printk("\tnew port(%d)\n", bpf_ntohs(nat->new_port));

    bpf_printk("\n");
}

static __always_inline void
set_fib(struct iphdr *iph, struct bpf_fib_lookup *fib) {

    fib->family      = AF_INET;
    fib->tos         = iph->tos;
    fib->l4_protocol = iph->protocol;
    fib->sport       = 0;
    fib->dport       = 0;
    fib->tot_len     = bpf_ntohs(iph->tot_len);
    fib->ipv4_src    = iph->saddr;
    fib->ipv4_dst    = iph->daddr;
}

static __always_inline int
fib_lookup(struct xdp_md *ctx, struct bpf_fib_lookup *fib, __u32 flags) {
    int rc;
    rc = bpf_fib_lookup(ctx, fib, sizeof(*fib), flags);

    bpf_printk("INFO: bpf_fib_lookup return code(%d)\n", rc);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            bpf_printk("\tBPF_FIB_LKUP_RET_SUCCESS\n");
            return XDP_REDIRECT;
        case BPF_FIB_LKUP_RET_BLACKHOLE:
            bpf_printk("\tBPF_FIB_LKUP_RET_BLACKHOLE\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_UNREACHABLE:
            return XDP_DROP;
            bpf_printk("\tBPF_FIB_LKUP_RET_UNREACHABLE\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_PROHIBIT:
            bpf_printk("\tBPF_FIB_LKUP_RET_PROHIBIT\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
            bpf_printk("\tBPF_FIB_LKUP_RET_NOT_FWDED\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
            bpf_printk("\tBPF_FIB_LKUP_RET_FWD_DISABLED\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
            bpf_printk("\tBPF_FIB_LKUP_RET_UNSUPP_LWT\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_NO_NEIGH:
            bpf_printk("\tBPF_FIB_LKUP_RET_NO_NEIGH\n");
            return XDP_PASS;
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            bpf_printk("\tBPF_FIB_LKUP_RET_FRAG_NEEDED\n");
            // pass
            return XDP_PASS;
    }
    return rc;
}

static __always_inline int
update_eth(struct ethhdr *eth,
           struct bpf_fib_lookup *fib,
           struct nat_info *nat) {

    memcpy(nat->seth, eth->h_source, ETH_ALEN);
    memcpy(nat->deth, eth->h_dest, ETH_ALEN);

    memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
    memcpy(eth->h_source, fib->smac, ETH_ALEN);

    return 0;
}
static __always_inline int
update_ipv4_checksum(struct iphdr *old, struct iphdr *new) {

    bpf_printk("old src ip(0x%x)\n", old->daddr);
    bpf_printk("old dst ip(0x%x)\n", new->daddr);

    l3_csum_replace(&new->check, old->daddr, new->daddr, sizeof(new->daddr));

    return 0;
}

static __always_inline __be16
update_icmp_id(struct icmphdr *hdr, __be16 new_port) {
    hdr->un.echo.id = new_port;

    return 0;
}

// static __always_inline int
// update_icmp_checksum(struct icmphdr hdr, struct icmphdr *new_hdr) {

//     __sum16 old_csum;

//     old_csum = old_hdr->checksum;

//     old_hdr->checksum = 0;
//     new_hdr->checksum = 0;

//     new_hdr->checksum =
//         generic_checksum(new_hdr, old_hdr, sizeof(struct icmphdr), old_csum);

//     return 0;
// }

// static __always_inline int
// update_tcp_checksum(struct tcphdr *old, struct tcphdr *new) {
//     __sum16 old_csum;
//     old_csum = old->check;

//     old->check = 0;
//     new->check = 0;

//     new->check = generic_checksum(new, old, sizeof(struct tcphdr), old_csum);
//     return 0;
// }
static __always_inline __be16
get_new_port(__be16 port_pool_key) {
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
            free_port = *find_port;
            bpf_printk("INFO: Exist port (%ld) -> (%ld)\n",
                       bpf_ntohs(port_pool_key),
                       bpf_ntohs(*find_port));
        }
    }

    return free_port;
}
static __always_inline int
update_icmp(struct hdr_cursor *nh, void *data_end, struct nat_info *nat) {
    struct icmphdr *icmphdr;
    struct icmphdr old_icmphdr;

    icmphdr = nh->pos;

    if (icmphdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    nh->pos = icmphdr + 1;

    old_icmphdr = *icmphdr;

    nat->sport    = icmphdr->un.echo.id;
    nat->dport    = 0;
    nat->new_port = get_new_port(nat->sport);

    if (nat->new_port > 0) {
        update_icmp_id(icmphdr, nat->new_port);

        l4_csum_replace(&icmphdr->checksum,
                        nat->sport,
                        nat->new_port,
                        sizeof(nat->new_port));

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

static __always_inline int
ingress_update_udp(struct hdr_cursor *nh,
                   void *data_end,
                   struct nat_info *nat) {
    struct udphdr *hdr = nh->pos;
    struct udphdr old_hdr;

    if (hdr + 1 > (struct udphdr *) data_end) {
        return -1;
    }

    nh->pos = hdr + 1;

    old_hdr = *hdr;

    nat->sport = hdr->source;
    nat->dport = hdr->dest;

    nat->new_port = get_new_port(nat->sport);

    bpf_printk("INFO: UDP old sport(%d) dport(%d) csum(0x%x)\n",
               bpf_ntohs(hdr->source),
               bpf_ntohs(hdr->dest),
               bpf_ntohs(hdr->check));

    bpf_printk("INFO: UDP len(%d)\n", bpf_ntohs(hdr->len) - sizeof(*hdr));
    if (nat->new_port > 0) {
        hdr->source = nat->new_port;

        __sum16 csum = hdr->check;
        bpf_printk(
            "INFO: old-addr(0x%x) new-addr(0x%x)\n", nat->saddr, nat->new_addr);
        bpf_printk("INFO: old-port(%d) new-port(%d)\n",
                   bpf_ntohs(nat->sport),
                   bpf_ntohs(nat->new_port));

        l4_csum_replace(
            &csum, nat->sport, nat->new_port, sizeof(nat->new_port));

        l4_csum_replace(&csum,
                        bpf_ntohl(nat->saddr),
                        bpf_ntohl(nat->new_addr),
                        IS_PSEUDO | sizeof(nat->saddr));

        hdr->check = csum;
        bpf_printk("INFO: UDP new sport(%d) dport(%d) csum(0x%x)\n",
                   bpf_ntohs(hdr->source),
                   bpf_ntohs(hdr->dest),
                   bpf_ntohs(hdr->check));

    } else {
        return -1;
    }
    return 0;
}

static __always_inline int
ingress_update_tcp(struct hdr_cursor *nh,
                   void *data_end,
                   struct nat_info *nat) {
    struct tcphdr *hdr = nh->pos;
    struct tcphdr old_hdr;

    if (hdr + 1 > (struct tcphdr *) data_end) {
        return -1;
    }

    nh->pos = hdr + 1;

    old_hdr = *hdr;

    nat->sport = hdr->source;
    nat->dport = hdr->dest;

    nat->new_port = get_new_port(nat->sport);

    bpf_printk("INFO: TCP old sport(%d) dport(%d) csum(0x%x)\n",
               bpf_ntohs(hdr->source),
               bpf_ntohs(hdr->dest),
               bpf_ntohs(hdr->check));

    if (nat->new_port > 0) {
        hdr->source = nat->new_port;

        l4_csum_replace(
            &hdr->check, nat->sport, nat->new_port, sizeof(nat->new_port));

        l4_csum_replace(&hdr->check,
                        // nat->saddr,
                        // nat->new_addr,
                        bpf_ntohl(nat->saddr),
                        bpf_ntohl(nat->new_addr),
                        sizeof(nat->new_addr) | IS_PSEUDO);
        bpf_printk("INFO: TCP new sport(%d) dport(%d) csum(0x%x)\n",
                   bpf_ntohs(hdr->source),
                   bpf_ntohs(hdr->dest),
                   bpf_ntohs(hdr->check));

    } else {
        return -1;
    }
    return 0;
}

static __always_inline int
update_ipv4(struct iphdr *iph, __u32 ifindex, struct nat_info *nat) {
    struct iphdr old_iphdr;
    struct ifinfo *info;

    old_iphdr = *iph;

    nat->saddr = iph->saddr;
    nat->daddr = iph->daddr;

    info = bpf_map_lookup_elem(&if_map, &ifindex);
    if (!info) {
        return -1;
    }

    bpf_printk("INFO: IP old checksum (0x%x)\n", iph->check);

    nat->new_addr = info->ip;
    iph->saddr    = info->ip;

    l3_csum_replace(
        &iph->check, nat->saddr, nat->new_addr, sizeof(nat->new_addr));

    bpf_printk("INFO: IP new checksum (0x%x)\n", iph->check);

    _print_iphdr(iph);

    return 0;
}

static __always_inline int
update_l4(struct hdr_cursor *nh,
          void *data_end,
          __u8 l4_protocol,
          struct nat_info *nat) {

    nat->proto = l4_protocol;
    switch (l4_protocol) {
        case IPPROTO_ICMP:
            bpf_printk("INFO: ICMP Ingress update\n");
            if (update_icmp(nh, data_end, nat) < 0) {
                bpf_printk("ERR: update icmp failed\n");
                return -1;
            }
            break;
        case IPPROTO_UDP:
            bpf_printk("INFO: UDP Ingress update\n");
            if (ingress_update_udp(nh, data_end, nat) < 0) {
                bpf_printk("ERR: update udp failed\n");
                return -1;
            }
            break;
        case IPPROTO_TCP:
            bpf_printk("INFO: TCP Ingress update\n");
            if (ingress_update_tcp(nh, data_end, nat) < 0) {
                bpf_printk("ERR: update tcp failed\n");
                return -1;
            }
            break;
    }
    return 0;
}

static __always_inline int
next_hop_lookup(struct xdp_md *ctx, struct bpf_fib_lookup *fib, __u32 flags) {

    return fib_lookup(ctx, fib, flags);
}

static __always_inline int
update_nat_map(struct nat_info *nat, struct nm_k *key) {
    return bpf_map_update_elem(&nat_map, key, nat, BPF_NOEXIST);
}

static __always_inline int
egress_get_icmp_id(struct hdr_cursor *nh, void *data_end, __be16 *port) {

    struct icmphdr *icmph = nh->pos;
    if (icmph + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    *port = icmph->un.echo.id;

    return 0;
}
static __always_inline int
egress_get_udp_port(struct hdr_cursor *nh, void *data_end, __be16 *port) {

    struct udphdr *udphdr = nh->pos;
    if (udphdr + 1 > (struct udphdr *) data_end) {
        return -1;
    }
    *port = udphdr->dest;
    return 0;
}

static __always_inline int
egress_get_tcp_port(struct hdr_cursor *nh, void *data_end, __be16 *port) {
    struct tcphdr *hdr = nh->pos;
    if (hdr + 1 > (struct tcphdr *) data_end) {
        return -1;
    }
    *port = hdr->dest;
    return 0;
}

static __always_inline int
get_l4_port(struct hdr_cursor *nh,
            void *data_end,
            __u8 protocol,
            __be16 *port) {

    switch (protocol) {
        case IPPROTO_ICMP:
            if (egress_get_icmp_id(nh, data_end, port) < 0) {
                return -1;
            }
            break;
        case IPPROTO_TCP:
            if (egress_get_tcp_port(nh, data_end, port) < 0) {
                return -1;
            }
            break;
        case IPPROTO_UDP:
            if (egress_get_udp_port(nh, data_end, port) < 0) {
                return -1;
            }
            break;
    }

    return 0;
}

static __always_inline int
egress_update_icmp(struct hdr_cursor *nh, void *data_end, __be16 port) {
    struct icmphdr *hdr;
    struct icmphdr old_hdr;
    hdr = nh->pos;
    if (hdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    old_hdr = *hdr;

    hdr->un.echo.id = port;

    l4_csum_replace(&hdr->checksum, hdr->un.echo.id, port, sizeof(port));

    return 0;
}

static __always_inline int
egress_update_tcp(struct hdr_cursor *nh,
                  void *data_end,
                  __be16 port,
                  struct nat_info *nat) {

    struct tcphdr *new = nh->pos;
    // struct tcphdr old;
    if (new + 1 > (struct tcphdr *) data_end) {
        return -1;
    }

    // old       = *new;

    bpf_printk("INFO: TCP update(0x%x:%d)\n",
               bpf_ntohl(nat->saddr),
               bpf_ntohs(new->dest));

    bpf_printk("INFO: Change from dest addr(0x%x) to (0x%x)\n",
               bpf_ntohl(nat->new_addr),
               bpf_ntohl(nat->saddr));
    bpf_printk("INFO: Change from dest port(%d) to (%d)\n",
               bpf_ntohs(nat->new_port),
               bpf_ntohs(port));
    l4_csum_replace(&new->check, nat->new_port, port, sizeof(port));

    l4_csum_replace(&new->check,
                    // nat->daddr,
                    // nat->saddr,
                    bpf_ntohl(nat->new_addr),
                    bpf_ntohl(nat->saddr),
                    sizeof(nat->saddr) | IS_PSEUDO);

    new->dest = port;
    return 0;
}
static __always_inline int
egress_update_udp(struct hdr_cursor *nh,
                  void *data_end,
                  __be16 port,
                  struct nat_info *nat) {
    struct udphdr *new = nh->pos;
    struct udphdr old;
    if (new + 1 > (struct udphdr *) data_end) {
        return -1;
    }

    old       = *new;
    new->dest = port;

    l4_csum_replace(&new->check, nat->sport, port, sizeof(port));
    l4_csum_replace(&new->check,
                    bpf_ntohl(nat->daddr),
                    bpf_ntohl(nat->saddr),
                    sizeof(nat->saddr) | IS_PSEUDO);

    return 0;
}

static __always_inline int
egress_update_l4(struct hdr_cursor *nh,
                 void *data_end,
                 __u8 protocol,
                 __be16 port,
                 struct nat_info *nat) {

    switch (protocol) {
        case IPPROTO_ICMP:
            bpf_printk("INFO: ICMP Egress update\n");
            if (egress_update_icmp(nh, data_end, port) < 0) {
                return -1;
            }
            break;
        case IPPROTO_UDP:
            bpf_printk("INFO: UDP Egress update\n");
            if (egress_update_udp(nh, data_end, port, nat) < 0) {
                return -1;
            }
            break;
        case IPPROTO_TCP:
            bpf_printk("INFO: TCP Egress update\n");
            if (egress_update_tcp(nh, data_end, port, nat) < 0) {
                return -1;
            }

            break;
    }
    return 0;
}

SEC("xnat/nat/ingress")
int
xnat_nat_ingress(struct xdp_md *ctx) {

    bpf_printk("SEC: xnat/nat/ingress\n");
    struct nat_info nat = {0};

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct hdr_cursor nh;
    struct ethhdr *eth;

    __u32 ingress_ifindex;
    __u32 *egress_ifindex;
    int action;
    __be16 h_proto;
    int err;

    action              = XDP_PASS;
    nh.pos              = data;
    ingress_ifindex     = ctx->ingress_ifindex;
    nat.ingress_ifindex = ingress_ifindex;

    bpf_printk("INFO: ingress ifindex(%d)\n", ingress_ifindex);

    egress_ifindex = bpf_map_lookup_elem(&tx_map, &ingress_ifindex);
    if (!egress_ifindex) {
        bpf_printk("ERR: lookup egress ifindex failed\n");
        goto err;
    }
    nat.egress_ifindex = *egress_ifindex;

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
    int return_code           = 0;

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

            return_code = next_hop_lookup(ctx, &fib, BPF_FIB_LOOKUP_OUTPUT);

            _print_fib(&fib);

            if (return_code != XDP_REDIRECT) {
                action = return_code;
                goto out;
            }
            if (update_ipv4(iph, *egress_ifindex, &nat) < 0) {
                bpf_printk("ERR: update_ipv4 failed\n");
                goto err;
            }

            if (update_l4(&nh, data_end, l4_protocol, &nat) < 0) {
                bpf_printk("ERR: update_l4 failed\n");
                goto err;
            }

            break;
        case ETH_P_IPV6:
            break;
        default:
            bpf_printk("INFO: Default\n");
            goto out;
    }

    bpf_printk("INFO: update_eth\n");
    if (update_eth(eth, &fib, &nat) < 0) {
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
    }

    action = bpf_redirect_map(&tx_map, ingress_ifindex, 0);

    goto out;
err:
    action = XDP_ABORTED;
out:
    return stats(ctx, &stats_map, action);
    // return action;
}

SEC("xnat/nat/egress")
int
xnat_nat_egress(struct xdp_md *ctx) {

    int action = XDP_PASS;

    bpf_printk("SEC: xnat/nat/egress\n");

    void *data     = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    __be16 h_proto;
    int err;

    __u32 egress_ifindex;
    __u32 *ingress_ifindex;

    nh.pos         = data;
    egress_ifindex = ctx->ingress_ifindex;
    bpf_printk("INFO: egress ifindex(%d)\n", egress_ifindex);

    // VLAN剥がす
    h_proto = parse_ethhdr(&nh, data_end, &eth);
    if (eth + 1 > (struct ethhdr *) data_end) {
        goto err;
    }

    struct nat_info *nat_info;
    __u8 l4_protocol;
    __be16 l4_port;
    struct iphdr *iph;

    l4_protocol = 0;
    l4_port     = 0;

    if (bpf_ntohs(h_proto) == ETH_P_ARP) {
        goto out;
    }
    if (bpf_ntohs(h_proto) == ETH_P_IP) {
        // nat-tableチェック
        // あればip, portなど修正してリダイレクト
        // なければegressのfibチェック
        iph = nh.pos;
        if (iph + 1 > (struct iphdr *) data_end) goto err;
        nh.pos = iph + 1;

        // ICMP/UDP/TCP判別に使う
        // IPPROTO_*
        l4_protocol = iph->protocol;

        // 宛先ポート番号取得
        // natテーブルから検索するキーになる
        err = get_l4_port(&nh, data_end, l4_protocol, &l4_port);

        if (err < 0) {
            bpf_printk("ERR: get_l4_port\n");
            goto err;
        }

        bpf_printk("Look up nat-table (0x%x:%d)\n",
                   bpf_ntohl(iph->daddr),
                   bpf_ntohs(l4_port));

        struct nm_k key = {
            .addr = iph->daddr,
            .port = l4_port,
        };

        nat_info = bpf_map_lookup_elem(&nat_map, &key);
        if (!nat_info) {
            bpf_printk(
                "ERR: bpf_map_lookup_elem faild or Not found "
                "nat-info(0x%x:%d)\n",
                bpf_ntohl(key.addr),
                bpf_ntohl(key.port));
            goto err;
        }

        bpf_printk("DEBUG: Found nat info\n");

        // ポート番号の変更、チェックサム再計算
        err = egress_update_l4(
            &nh, data_end, l4_protocol, nat_info->sport, nat_info);
        if (err < 0) {
            goto err;
        }

        ingress_ifindex = bpf_map_lookup_elem(&tx_map, &egress_ifindex);
        if (!ingress_ifindex) {
            goto err;
        }

        bpf_printk("DEBUG: ingress_ifindex(%d)\n", *ingress_ifindex);

        struct ifinfo *info;
        info = bpf_map_lookup_elem(&if_map, ingress_ifindex);
        if (!info) {
            goto err;
        }

        struct iphdr old_iphdr;
        old_iphdr  = *iph;
        iph->daddr = nat_info->saddr;

        update_ipv4_checksum(&old_iphdr, iph);

        bpf_printk("INFO: egress saddr(0x%x)\n", bpf_ntohl(iph->saddr));
        bpf_printk("INFO: egress daddr(0x%x)\n", bpf_ntohl(iph->daddr));

        memcpy(eth->h_source, info->mac, ETH_ALEN);
        memcpy(eth->h_dest, nat_info->seth, ETH_ALEN);
    }
    action = bpf_redirect_map(&tx_map, egress_ifindex, 0);

    goto out;
err:

    action = XDP_ABORTED;
out:
    return stats(ctx, &stats_map, action);
}

SEC("xnat/root/ingress")
int
xnat_root_ingress(struct xdp_md *ctx) {
    bpf_printk("SEC: xnat/root/ingress\n");
    bpf_tail_call(ctx, &ingress_prog_map, 0);
    return XDP_ABORTED;
}
SEC("xnat/root/egress")
int
xnat_root_egress(struct xdp_md *ctx) {
    bpf_printk("SEC: xnat/root/egress\n");
    bpf_tail_call(ctx, &egress_prog_map, 0);
    return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
