#ifndef __PARSER_H
#define __PARSER_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_endian.h"

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

struct hdr_cursor {
    void *pos;
};

struct icmphdr_common {
    __u8 type;
    __u8 code;
    __sum16 cksum;
};

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct arp_hdr {
    __be16 hrd;
    __be16 pro;
    __u8 hln;
    __u8 pln;
    __be16 op;
    __u8 sha[ETH_ALEN];
    __be32 sip;
    __u8 tha[ETH_ALEN];
    __be32 tip;
} __attribute__((packed));

static __always_inline int
proto_is_vlan(__u16 h_proto) {
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
              h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline __be16
parse_ethhdr(struct hdr_cursor *nh,
             void *data_end,
             struct ethhdr **ethhdr,
             __u16 *vid) {

    struct ethhdr *h = (struct ethhdr *) nh->pos;
    struct vlan_hdr *vlh;
    __be16 h_proto;

    if (h + 1 > (struct ethhdr *) data_end) return -1;

    nh->pos = h + 1;
    *ethhdr = h;
    vlh     = (struct vlan_hdr *) nh->pos;
    h_proto = h->h_proto;

#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan(h_proto)) break;

        if (vlh + 1 > (struct vlan_hdr *) data_end) break;

        bpf_printk("vlan_TCI(0x%x)\n", vlh->h_vlan_TCI);

        h_proto = vlh->h_vlan_encapsulated_proto;
        // *vid    = bpf_htons(vlh->h_vlan_TCI) & 0x0fff;
        vlh++;
    }

    nh->pos = vlh;
    return h_proto;
}

static __always_inline int
parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr) {

    struct ipv6hdr *h = (struct ipv6hdr *) nh->pos;

    if (h + 1 > (struct ipv6hdr *) data_end) return -1;

    nh->pos = h + 1;
    *ip6hdr = h;
    return h->nexthdr;
}

static __always_inline int
parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr) {
    struct iphdr *h = (struct iphdr *) nh->pos;
    int hdrsize;

    if (h + 1 > (struct iphdr *) data_end) return -1;

    hdrsize = h->ihl * 4;

    if (nh->pos + hdrsize > data_end) return -1;

    nh->pos += hdrsize;
    *iphdr = h;

    return h->protocol;
}

static __always_inline int
parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmphdr) {

    struct icmphdr *h = (struct icmphdr *) nh->pos;

    if (h + 1 > (struct icmphdr *) data_end) return -1;

    nh->pos  = (struct icmphdr *) h + 1;
    *icmphdr = h;

    return h->type;
}
static __always_inline int
parse_icmphdr_common(struct hdr_cursor *nh,
                     void *data_end,
                     struct icmphdr_common **icmphdr) {

    struct icmphdr_common *h = (struct icmphdr_common *) nh->pos;

    if (h + 1 > (struct icmphdr_common *) data_end) return -1;

    nh->pos  = h + 1;
    *icmphdr = h;

    return h->type;
}

#endif /* end of include guard */
