#ifndef __ICMP_H
#define __ICMP_H

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

static __always_inline __u32 update_icmp_checksum(struct icmphdr *old_hdr,
                                                  struct icmphdr *new_hdr) {

    __sum16 old_csum;

    old_csum          = old_hdr->checksum;
    old_hdr->checksum = 0;
    new_hdr->checksum = 0;

    new_hdr->checksum =
        generic_checksum(new_hdr, old_hdr, sizeof(struct icmphdr), old_csum);

    return 0;
}

static __always_inline __u32 update_icmp(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct nat_table *nt) {
    struct icmphdr *icmphdr;
    struct icmphdr old_icmphdr;

    icmphdr = nh->pos;

    if (icmphdr + 1 > (struct icmphdr *) data_end) {
        return -1;
    }

    old_icmphdr = *icmphdr;

    nt->proto    = IPPROTO_ICMP;
    nt->sport    = get_icmp_id(nh, data_end, &icmphdr);
    nt->dport    = 0;
    nt->new_port = get_new_port(nt->sport);

    if (nt->new_port > 0) {
        update_icmp_id(icmphdr, nt->new_port);

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

#endif /* end of include guard */
