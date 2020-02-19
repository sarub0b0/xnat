#ifndef __LPM_TRIE_H
#define __LPM_TRIE_H

struct lpm_trie_key {
    __u32 prefixlen;
    __u8 data[4];
};

struct lpm_trie_value {
    __u32 ifindex;
    __u16 vid;
};

// destination address -> egress vid & vip

#endif /* end of include guard */
