#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#include "stats.h"
#include "message.h"

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

const char *dev_name    = "xnat1";
const char *pin_basedir = "/sys/fs/bpf";

struct bpf_prog_load_attr prog_load_attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    .file      = "xnat_ext_kern.o",
};

int pin_maps_in_bpf_object(struct bpf_object *obj, const char *subdir) {
    char map_filename[PATH_MAX];
    char pin_dir[PATH_MAX];
    int err, len;
    struct bpf_map *map;

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
    if (len < 0) {
        err("creating map dirname");
        return EXIT_FAIL_OPTION;
    }

    bpf_map__for_each(map, obj) {
        const char *map_name = bpf_map__name(map);

        map = bpf_object__find_map_by_name(obj, map_name);
        if (!map) {
            fprintf(stderr,
                    "ERR: bpf_object__find_map_by_name failed. [%s]\n",
                    map_name);
            return EXIT_FAIL_BPF;
        }
        len = snprintf(
            map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, subdir, map_name);
        if (len < 0) {
            err("creating map name");
            return EXIT_FAIL_OPTION;
        }
    }

    if (access(map_filename, F_OK) != -1) {
        info(" - Unpinning (remove) prev maps in %s", pin_dir);
        err = bpf_object__unpin_maps(obj, pin_dir);
        if (err) {
            err("Unpinning maps in %s", pin_dir);
            return EXIT_FAIL_OPTION;
        }
    }
    info(" - Pinning maps in %s", pin_dir);

    err = bpf_object__pin_maps(obj, pin_dir);
    if (err) {
        return EXIT_FAIL_BPF;
    }
    return 0;
}

int main(int argc, char const *argv[]) {
    int prog_fd = -1;
    struct bpf_object *obj;
    int ifindex;

    int err;

    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
        fprintf(stderr, "ERR: bpf_prog_load_xattr faild\n");
        return EXIT_FAIL_BPF;
    }

    ifindex = if_nametoindex(dev_name);
    if (!ifindex) {
        fprintf(stderr, "ERR: unknown interface %s\n", dev_name);
        return EXIT_FAIL_OPTION;
    }

    fprintf(stdout, "if=%s/%d\n", dev_name, ifindex);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        fprintf(stderr,
                "ERR: Can't attach to interface %s:%d\n",
                dev_name,
                ifindex);
        return EXIT_FAIL_BPF;
    }

    err = pin_maps_in_bpf_object(obj, dev_name);
    if (err) {
        return EXIT_FAIL_BPF;
    }

    return 0;
}
