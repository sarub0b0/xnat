
#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include <stdbool.h>

#include "bpf_helpers.h"

#include "printk.h"

#include "parser.h"
#include "nat.h"

#define CSUM_MANGLED_0 ((__sum16) 0xffff)
#define IS_PSEUDO 0x10

static __always_inline __wsum
generic_checksum(void *new_val, void *old_val, int size, __wsum seed) {

    __wsum csum = 0;

    csum = bpf_csum_diff(old_val, size, new_val, size, ~seed);

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    return ~csum;
}

static __always_inline __u32
rfc1071_checksum(void *hdr, int size, __u32 seed) {
    // RFC 1071
    // int checksum(unsigned short *buf, int bufsize) {
    __u32 sum = seed;

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

static __always_inline __wsum
csum_partial(void *buf, int len, __wsum wsum) {
    __u32 sum    = (__u32) wsum;
    __u32 result = rfc1071_checksum(buf, len, 0);

    result += sum;
    if (sum > result) {
        result += 1;
    }
    return (__wsum) result;
}

static __always_inline __sum16
csum_fold(__wsum csum) {
    __u32 sum = (__u32) csum;
    sum       = (sum & 0xffff) + (sum >> 16);
    sum       = (sum & 0xffff) + (sum >> 16);
    return (__sum16) ~sum;
}

static __always_inline __wsum
csum_unfold(__sum16 csum) {
    return (__wsum) csum;
}

static __always_inline __wsum
csum_add(__wsum csum, __wsum addend) {
    __u32 res = (__u32) csum;
    res += (__u32) addend;
    return (__wsum)(res + (res < (__u32) addend));
}
static __always_inline __wsum
csum_sub(__wsum csum, __wsum addend) {
    return csum_add(csum, ~addend);
}

static __always_inline __sum16
csum16_add(__sum16 csum, __be16 addend) {
    __u16 res = (__u16) csum;
    res += (__u16) addend;
    return (__sum16)(res + (res < (__u16) addend));
}
static __always_inline __sum16
csum16_sub(__sum16 csum, __be16 addend) {
    return csum16_add(csum, ~addend);
}

static __always_inline void
csum_replace4(__sum16 *sum, __be32 from, __be32 to) {
    __wsum tmp = csum_sub(~csum_unfold(*sum), (__wsum) from);
    *sum       = csum_fold(csum_add(tmp, (__wsum) to));
}

static __always_inline void
csum_replace2(__sum16 *sum, __be16 from, __be16 to) {
    *sum = ~csum16_add(csum16_sub(~(*sum), from), to);
}

static __always_inline void
csum_replace_by_diff(__sum16 *sum, __wsum diff) {
    *sum = csum_fold(csum_add(diff, csum_unfold(*sum)));
}

static __always_inline void
inet_proto_csum_replace4(__sum16 *sum, __be32 from, __be32 to, bool pseudohdr) {
    if (pseudohdr) {
        *sum = ~csum_fold(
            csum_add(csum_sub(csum_unfold(*sum), (__wsum) from), (__wsum) to));

    } else {
        csum_replace4(sum, from, to);
    }
}

static __always_inline void
inet_proto_csum_replace2(__sum16 *sum, __be16 from, __be16 to, bool pseudohdr) {

    inet_proto_csum_replace4(sum, (__be32) from, (__be32) to, pseudohdr);
}

static __always_inline void
inet_proto_csum_replace_by_diff(__sum16 *sum, __wsum diff, bool pseudohdr) {
    if (pseudohdr)
        *sum = ~csum_fold(csum_add(diff, csum_unfold(*sum)));
    else
        *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static __always_inline int
l4_csum_replace(__sum16 *sum, __be32 old_value, __be32 new_value, __u32 flags) {

    bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
    bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
    bool do_mforce = flags & BPF_F_MARK_ENFORCE;

    if (is_mmzero) {
        bpf_printk("DEBUG: BPF_F_MARK_MANGLED_0\n");
    }
    if (is_pseudo) {
        bpf_printk("DEBUG: BPF_F_PSEUDO_HDR\n");
    }
    if (do_mforce) {
        bpf_printk("DEBUG: BPF_F_MARK_ENFORCE\n");
    }

    if (flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE | BPF_F_PSEUDO_HDR |
                  BPF_F_HDR_FIELD_MASK))
        return -EINVAL;

    if (is_mmzero && !do_mforce && !*sum) return 0;

    switch (flags & BPF_F_HDR_FIELD_MASK) {
        case 0:
            if (old_value != 0) return -EINVAL;

            // ref. kernel code: net/core/filter.c
            // ref. kernel code: net/core/utils.c
            // inet_proto_csum_replace_by_diff(ptr, skb, to, is_pseudo);
            inet_proto_csum_replace_by_diff(sum, new_value, is_pseudo);
            break;
        case 2:
            // ref. kernel code: net/core/filter.c
            // ref. kernel code: net/core/utils.c
            // inet_proto_csum_replace2(ptr, skb, from, to, is_pseudo);
            inet_proto_csum_replace2(sum, old_value, new_value, is_pseudo);
            break;
        case 4:
            // ref. kernel code: net/core/filter.c
            // ref. kernel code: net/core/utils.c
            // inet_proto_csum_replace4(ptr, skb, from, to, is_pseudo);
            inet_proto_csum_replace4(sum, old_value, new_value, is_pseudo);
            break;
        default:
            return -EINVAL;
    }

    if (is_mmzero && !*sum) {
        *sum = CSUM_MANGLED_0;
    }
    return 0;
}

static __always_inline int
l3_csum_replace(__sum16 *sum, __be32 old_value, __be32 new_value, __u32 flags) {

    if (flags & ~(BPF_F_HDR_FIELD_MASK)) return -EINVAL;

    switch (flags & BPF_F_HDR_FIELD_MASK) {
        case 0:
            // csum_replace_by_diff(sum, new_value);
            csum_replace_by_diff(sum, new_value);
            break;
        case 2:
            // *sum = ~csum16_add(csum16_add(~(*sum), ~old_value), new_value);
            csum_replace2(sum, old_value, new_value);
            break;
        case 4:
            // csum_replace_by_diff(sum, csum_add(new_value, ~old_value));
            csum_replace4(sum, old_value, new_value);
            break;
        default:
            return -1;
    }
    return 0;
}

#endif /* end of include guard */
