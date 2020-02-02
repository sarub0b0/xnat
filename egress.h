#ifndef __EGRESS_H
#define __EGRESS_H

#include "prog.h"
struct bpf_map_def SEC("maps") egress_prog_map = {
    .type        = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_PROGS,
};


#endif /* end of include guard */
