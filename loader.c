#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <getopt.h>

#include "message.h"

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#define PATH_MAX 128
#define DEV_MAX 32

// #define XDP_UNKNOWN (XDP_REDIRECT + 1)
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

const char *pin_basedir = "/sys/fs/bpf";
char *ingress_progsec   = "xnat/ingress";
char *egress_progsec    = "xnat/egress";

// char *ingress_progsec = "pass";
// char *egress_progsec = "drop";

struct config {
    // __u32 xdp_flags;
    // int ifindex;
    // char *ifname;
    // char ifname_buf[IF_NAMESIZE];
    // int redirect_ifindex;
    // char *redirect_ifname;
    // char redirect_ifname_buf[IF_NAMESIZE];
    // char pin_dir[PATH_MAX];
    // char filename[PATH_MAX];
    // char progsec[PATH_MAX];
    // char src_mac[18];
    // char dest_mac[18];
    char sub_dir[PATH_MAX];
    char obj_name[PATH_MAX];
    char ingress_devname[DEV_MAX];
    char egress_devname[DEV_MAX];
};

struct bpf_prog_load_attr prog_load_attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    .file      = NULL,
};

struct option long_options[] = {
    {"int-dev", required_argument, NULL, 'i'},
    {"ext-dev", required_argument, NULL, 'e'},
    {"obj", required_argument, NULL, 'o'},
    {"sub-dir", required_argument, NULL, 'd'},
    {"help", no_argument, NULL, 'h'},
};

char short_options[] = "i:e:o:d:h";

void
usage(void) {
    printf("Usage: ./loader [options] (root permission)\n");
    printf("\n");
    printf("  Required options:\n");
    printf("    --int-dev, -i: ingress device name\n");
    printf("    --ext-dev, -e: egress device name\n");
    printf("    --obj,     -o: xdp object name\n");
    printf("    --sub-dir, -d: pininng map sub dir [base=/sys/fs/bpf]\n");
    printf("\n");
    printf("  Other options:\n");
    printf("    --help,    -h: help\n");
}

int
link_attach(struct config *cfg,
            struct bpf_object **obj,
            char *progsec,
            char *devname) {
    struct bpf_program *bpf_prog;
    int prog_fd;
    int ifindex;

    ifindex = if_nametoindex(devname);
    if (!ifindex) {
        info("ERR: unknown ingress interface %s", devname);
        return EXIT_FAIL_OPTION;
    }

    info("if=%s/%d", devname, ifindex);

    bpf_prog = bpf_object__find_program_by_title(*obj, progsec);
    if (!bpf_prog) {
        err("Couldn't find a program in ELF section '%s'", progsec);
        return EXIT_FAIL_BPF;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0) {
        err("bpf_program__fd failed");
        return EXIT_FAIL_BPF;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) < 0) {
        info("ERR: Can't attach to interface %s:%d",
             cfg->ingress_devname,
             ifindex);
        return EXIT_FAIL_BPF;
    }
    return 0;
}

int
pin_maps_in_bpf_object(struct bpf_object *obj, const char *subdir) {
    char map_filename[PATH_MAX];
    char pin_dir[PATH_MAX];
    int err, len;
    struct bpf_map *map;

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
    if (len < 0) {
        err("creating map dirname");
        return EXIT_FAIL_OPTION;
    }

    info("map pinned dir (%s)", pin_dir);

    bpf_map__for_each(map, obj) {
        const char *map_name = bpf_map__name(map);

        info("map-name [%s]", map_name);

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

int
main(int argc, char *const *argv) {

    struct config cfg;
    struct bpf_object *obj = NULL;

    int err;
    int len;

    int set_subdir  = 0;
    int set_devname = 0;
    int set_objname = 0;

    memset(&cfg, 0, sizeof(struct config));

    if (argc == 1) {
        usage();
        return 1;
    }

    int c;
    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) !=
           -1) {
        switch (c) {
            case 'i':
                len = snprintf(cfg.ingress_devname,
                               sizeof(cfg.ingress_devname),
                               "%s",
                               optarg);
                if (len < 0) {
                    return EXIT_FAIL_OPTION;
                }
                set_devname++;
                break;
            case 'e':
                len = snprintf(cfg.egress_devname,
                               sizeof(cfg.ingress_devname),
                               "%s",
                               optarg);
                if (len < 0) {
                    return EXIT_FAIL_OPTION;
                }
                set_devname++;
                break;

            case 'o':
                len = snprintf(cfg.obj_name, PATH_MAX, "%s", optarg);
                if (len < 0) {
                    return EXIT_FAIL_OPTION;
                }

                set_objname = 1;
                break;
            case 'd':
                len = snprintf(cfg.sub_dir, PATH_MAX, "%s", optarg);
                if (len < 0) {
                    return EXIT_FAIL_OPTION;
                }
                set_subdir = 1;
                break;
            case 'h':
                usage();
                return 1;
            default:
                usage();
                return EXIT_FAIL;
        }
    }

    if (set_subdir != 1 || set_objname != 1 || set_devname != 2) {
        err("Set ingress devname, egress devname, objname, subdir");
        return EXIT_FAIL;
    }

    info("Ingress device(%s)", cfg.ingress_devname);
    info("Egress device(%s)", cfg.egress_devname);

    int prog_fd;
    prog_load_attr.file = cfg.obj_name;
    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
        info("ERR: bpf_prog_load_xattr faild");
        return EXIT_FAIL_BPF;
    }

    err = link_attach(&cfg, &obj, ingress_progsec, cfg.ingress_devname);
    if (err > 0) {
        return EXIT_FAIL_BPF;
    }

    err = link_attach(&cfg, &obj, egress_progsec, cfg.egress_devname);
    if (err > 0) {
        return EXIT_FAIL_BPF;
    }

    err = pin_maps_in_bpf_object(obj, cfg.sub_dir);
    if (err > 0) {
        return EXIT_FAIL_BPF;
    }

    return 0;
}
