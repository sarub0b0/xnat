#ifndef __IFINFO_H
#define __IFINFO_H

struct ifinfo {
    __be32 ip;
    __u8 mac[ETH_ALEN];
};
#endif /* end of include guard */
