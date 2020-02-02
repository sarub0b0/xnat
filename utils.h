#ifndef __UTILS_H
#define __UTILS_H

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

#include <cstdint>
#include <string>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

#include "message.h"

static inline uint32_t
bpf_num_possible_cpus(void) {
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        err("Failed to get # of possible cpus: '%s'!", strerror(-cpus));
        return 0;
    }
    return static_cast<uint32_t>(cpus);
}

int
open_bpf_map_file(const std::string *pin_dir,
                  const std::string *map_name,
                  struct bpf_map_info *info) {

    int fd  = -1;
    int err = -1;

    std::string filename;
    uint32_t info_len = sizeof(*info);

    filename = *pin_dir + "/" + *map_name;
    if (filename.length() < 0) {
        err("constructing full map_name path");
        return -1;
    }

    fd = bpf_obj_get(filename.c_str());
    if (fd < 0) {
        err("failed to open bpf map file: %s err(%d):%s",
            filename.c_str(),
            errno,
            strerror(errno));
        return fd;
    }
    if (info) {
        err = bpf_obj_get_info_by_fd(fd, info, &info_len);
        if (err) {
            err("%s() can't get info - %s", __func__, strerror(errno));
            return EXIT_FAIL_BPF;
        }
    }

    return fd;
}

#endif
