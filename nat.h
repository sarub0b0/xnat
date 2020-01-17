#ifndef __NAT_H
#define __NAT_H

#include <linux/if_ether.h>

#include "bpf_endian.h"

struct nm_k {
    __be32 addr;
    __be16 port;
} __attribute__((packed));

struct nat_info {
    __u16 ingress_ifindex;
    __u16 egress_ifindex;
    __u8 seth[ETH_ALEN];
    __u8 deth[ETH_ALEN];
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __be16 proto;
    __be32 new_addr;
    __be16 new_port;
    // };
} __attribute__((packed, aligned(2)));

#endif /* end of include guard */
