#pragma once
#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

// #define XDP_UNKNOWN (XDP_REDIRECT + 1)
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#include <cstdio>
#include <cstdint>
#include <cstdlib>

#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "message.h"

inline uint32_t
bpf_num_possible_cpus(void) {
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        err("Failed to get # of possible cpus: '%s'!", strerror(-cpus));
        return 0;
    }
    return static_cast<uint32_t>(cpus);
}

