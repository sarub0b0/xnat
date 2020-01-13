#ifndef __NAT_H
#define __NAT_H

struct nat_table {
    int i_ifindex;
    int e_ifindex;
    unsigned char eth[ETH_ALEN];
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 proto;
    __be16 new_addr;
    __u16 new_port;
};

#endif /* end of include guard */
