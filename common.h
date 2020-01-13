
#ifndef __COMMON_H
#define __COMMON_H

#include "parser.h"

static __always_inline __u16 icmp_checksum(__u16 seed,
                                           struct icmphdr_common *new_icmphdr,
                                           struct icmphdr_common *old_icmphdr) {
    __u32 csum = 0;
    __u32 size = sizeof(struct icmphdr_common);
    csum       = bpf_csum_diff(old_icmphdr, size, new_icmphdr, size, seed);
    return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline int ip_checksum(struct iphdr *iph) {
    // RFC 1071
    // int checksum(unsigned short *buf, int bufsize) {
    int sum    = 0;
    iph->check = 0;

    __u16 *buf  = (__u16 *) iph;
    int bufsize = sizeof(*iph);

    while (bufsize > 1) {
        sum += *buf++;
        bufsize -= 2;
    }

    // if (bufsize > 0) {
    //     sum += *(__u8 *) buf;
    // }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    iph->check = ~sum;
    return 0;
}

#endif /* end of include guard */
