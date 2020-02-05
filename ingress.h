#ifndef __INGRESS_H
#define __INGRESS_H

#include "prog.h"

struct bpf_map_def SEC("maps") ingress_prog_array = {
    .type        = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_PROGS,
};


#endif /* end of include guard */
