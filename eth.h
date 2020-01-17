#ifndef __ETH_H
#define __ETH_H

static __always_inline __u32 update_eth(struct ethhdr *eth,
                                        struct nat_table *nt) {
    unsigned char *dst;
    unsigned char *src;

    memcpy(nt->seth, eth->h_source, ETH_ALEN);
    memcpy(nt->deth, eth->h_dest, ETH_ALEN);

    dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
    if (!dst) {
        bpf_printk("ERR: lookup source mac failed\n");
        return -1;
    }

    memcpy(eth->h_dest, dst, ETH_ALEN);

    src = bpf_map_lookup_elem(&redirect_params, eth->h_dest);
    if (!src) {
        bpf_printk("ERR: lookup dest mac failed\n");
        return -1;
    }

    memcpy(eth->h_source, src, ETH_ALEN);

    return 0;
}
// static __always_inline __u32 proxy_arp(struct hdr_cursor *nh,
//                                        void *data_end,
//                                        struct ethhdr *eth,
//                                        __u32 ingress_ifindex) {

//     int action = XDP_PASS;

//     struct ether_arp *arphdr = nh->pos;
//     bpf_printk("hdr len %d\n", data_end - nh->pos);
//     bpf_printk("arphdr len %d\n", sizeof(struct arphdr));
//     bpf_printk("ether_arp len %d\n", sizeof(struct ether_arp));
//     bpf_printk("__be32 len %d\n", sizeof(__be32));

//     bpf_printk("data_end %p\n", data_end);
//     bpf_printk("pos1 %p\n", (struct arphdr *) (nh->pos + 1));
//     bpf_printk("pos2 %p\n", (struct ether_arp *) (arphdr + 1));

//     if (arphdr + 1 > (struct ether_arp *) data_end) {
//         return -1;
//     }

//     arphdr->ar_hrd = bpf_htons(ARPHRD_ETHER);
//     arphdr->ar_pro = bpf_htons(0x0800);
//     arphdr->ar_hln = ETH_ALEN;
//     arphdr->ar_pln = 4;
//     arphdr->ar_op  = bpf_htons(ARPOP_REQUEST);

//     __u32 *egress_ifindex;

//     egress_ifindex = bpf_map_lookup_elem(&tx_map, &ingress_ifindex);
//     if (!egress_ifindex) {
//         bpf_printk("ERR: lookup egress ifindex failed\n");
//         return -1;
//     }

//     bpf_printk("egress_ifindex(%d)\n", *egress_ifindex);

//     struct ifinfo *info;
//     info = bpf_map_lookup_elem(&if_map, egress_ifindex);
//     if (!info) {
//         bpf_printk("ERR: lookup source mac failed\n");
//         return -1;
//     }

//     memcpy(arphdr->ar_sha, info->mac, ETH_ALEN);
//     memcpy(arphdr->ar_sip, &info->ip, sizeof(info->ip));

//     memset(arphdr->ar_tha, 0x00, ETH_ALEN);

//     bpf_printk("\n");
//     bpf_printk("==== arp header ====\n");
//     bpf_printk("\thardware address(0x%x)\n", arphdr->ar_hrd);
//     bpf_printk("\tprotocol address(0x%x)\n", bpf_ntohs(arphdr->ar_pro));
//     bpf_printk("\tlengeth of hardware address(%d)\n", arphdr->ar_hln);
//     bpf_printk("\tlengeth of protocol address(%d)\n", arphdr->ar_pln);
//     bpf_printk("\topcode(0x%x)\n", arphdr->ar_op);

//     bpf_printk("\tsender ha(%x:%x:%x)\n",
//                arphdr->ar_sha[0],
//                arphdr->ar_sha[1],
//                arphdr->ar_sha[2]);
//     bpf_printk("\tsender ha(%x:%x:%x)\n",
//                arphdr->ar_sha[3],
//                arphdr->ar_sha[4],
//                arphdr->ar_sha[5]);

//     bpf_printk("\tsender ip(%d.%d)\n", arphdr->ar_sip[0], arphdr->ar_sip[1]);
//     bpf_printk("\tsender ip(.%d.%d)\n", arphdr->ar_sip[2], arphdr->ar_sip[3]);

//     bpf_printk("\ttarget ha(%x:%x:%x)\n",
//                arphdr->ar_tha[0],
//                arphdr->ar_tha[1],
//                arphdr->ar_tha[2]);
//     bpf_printk("\ttarget ha(%x:%x:%x)\n",
//                arphdr->ar_tha[3],
//                arphdr->ar_tha[4],
//                arphdr->ar_tha[5]);

//     bpf_printk("\ttarget ip(%d.%d)\n", arphdr->ar_tip[0], arphdr->ar_tip[1]);
//     bpf_printk("\ttarget ip(.%d.%d)\n", arphdr->ar_tip[2], arphdr->ar_tip[3]);

//     memcpy(eth->h_source, info->mac, ETH_ALEN);
//     memset(eth->h_dest, 0xff, ETH_ALEN);

//     bpf_printk("src mac(%x:%x:%x:)\n",
//                eth->h_source[0],
//                eth->h_source[1],
//                eth->h_source[2]);
//     bpf_printk("src mac(%x:%x:%x)\n",
//                eth->h_source[3],
//                eth->h_source[4],
//                eth->h_source[5]);
//     bpf_printk(
//         "dst mac(%x:%x:%x:)\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
//     bpf_printk(
//         "dst mac(%x:%x:%x)\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

//     action = bpf_redirect_map(&tx_map, ingress_ifindex, 0);

//     bpf_printk("action(%d)\n", action);

//     return action;
// }


#endif /* end of include guard */
