#ifndef __IPV4_H
#define __IPV4_H

static __always_inline __u32 update_ipv4_checksum(struct iphdr *old,
                                                  struct iphdr *new) {
    __sum16 old_csum;

    old_csum   = old->check;
    old->check = 0;
    new->check = 0;

    new->check = generic_checksum(new, old, sizeof(struct iphdr), old_csum);
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

#endif /* end of include guard */
