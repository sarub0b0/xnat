
#ifndef __COMMON_H
#define __COMMON_H

#include "parser.h"

struct ether_arp {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __be16 ar_op;
    __u8 ar_sha[ETH_ALEN];
    __u8 ar_sip[4];
    __u8 ar_tha[ETH_ALEN];
    __u8 ar_tip[4];
};

static __always_inline __wsum generic_checksum(void *new,
                                               void *old,
                                               int size,
                                               __wsum seed) {

    __wsum csum = 0;

    csum = bpf_csum_diff(old, size, new, size, ~seed);

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    return ~csum;
}

static __always_inline __u32 rfc1071_checksum(void *hdr, int size) {
    // RFC 1071
    // int checksum(unsigned short *buf, int bufsize) {
    __u32 sum = 0;
    // iph->check = 0;

    __u16 *buf  = (__u16 *) hdr;
    int bufsize = size;

    while (bufsize > 1) {
        sum += *buf++;
        bufsize -= 2;
    }

    if (bufsize > 0) {
        sum += *(__u8 *) buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    return ~((sum & 0xffff) + (sum >> 16));
}

#endif /* end of include guard */
