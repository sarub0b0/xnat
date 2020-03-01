#ifndef __STATS_H
#define __STATS_H

#include <linux/bpf.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

#endif

