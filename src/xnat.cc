#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include "getopt_long.h"

#include "define.h"
#include "xnat.h"

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
    printf("    --native   -1: native mode (default generic mode)\n");
    printf(
        "    --remove,  -R: when xnat is killed, removed maps and detach xdp. "
        "default is false\n");
}
struct option long_options[] = {
    {"int-dev", required_argument, NULL, 'i'},
    {"ext-dev", required_argument, NULL, 'e'},
    {"obj", required_argument, NULL, 'o'},
    {"sub-dir", required_argument, NULL, 'd'},
    {"help", no_argument, NULL, 'h'},
    {"native", no_argument, NULL, 1},
    {"remove", no_argument, NULL, 'R'},
};

char short_options[] = "i:e:o:d:hR";

int
set_config(int argc, char *const *argv, struct config &cfg) {
    cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    cfg.rm_flag   = false;

    int c;
    while ((c = gopt.getopt_long(
                argc, argv, short_options, long_options, NULL)) != -1) {
        switch (c) {
            case 'i':
                if (!gopt.opt_arg) return ERROR;
                cfg.ingress_ifname = gopt.opt_arg;
                break;
            case 'e':
                if (!gopt.opt_arg) return ERROR;
                cfg.egress_ifname = gopt.opt_arg;
                break;
            case 'o':
                if (!gopt.opt_arg) return ERROR;
                cfg.load_obj_name = gopt.opt_arg;
                break;
            case 'd':
                if (!gopt.opt_arg) return ERROR;
                cfg.map_pin_dir = gopt.opt_arg;
                break;
            case 'h':
                usage();
                return SUCCESS;
            case 1:
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;
                cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;
                break;
            case 'R':
                cfg.rm_flag = true;
                break;
            default:
                usage();
                return ERROR;
        }
    }

    if (cfg.map_pin_dir.length() < 1 || cfg.ingress_ifname.length() < 1 ||
        cfg.egress_ifname.length() < 1 || cfg.load_obj_name.length() < 1) {
        err("Set ingress-ifname, egress-ifname, obj_name, sub_dir");
        return ERROR;
    }

    cfg.prog_load_attr.file      = cfg.load_obj_name.c_str();
    cfg.prog_load_attr.prog_type = BPF_PROG_TYPE_XDP;
    cfg.ingress_progsec          = "xnat/root/ingress";
    cfg.egress_progsec           = "xnat/root/egress";
    cfg.pin_basedir              = "/sys/fs/bpf";
    cfg.map_pin_dir              = cfg.pin_basedir + "/" + cfg.map_pin_dir;
    cfg.nr_cpus                  = bpf_num_possible_cpus();
    cfg.listen_address           = "0.0.0.0:10000";

    return SUCCESS;
}

int
main(int argc, char *const *argv) {

    struct rlimit lck_mem = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
        err("Can't change limit for locked memory");
        return ERROR;
    }

    struct config config = {};

    if (argc == 1) {
        usage();
        return ERROR;
    }

    if (set_config(argc, argv, config) < 0) return ERROR;

    class xnat::xnat xnat(config);

    try {
        xnat.load_bpf_progs();
        xnat.pin_maps();
        xnat.attach_bpf_progs();
        xnat.set_xnat_to_prog_array();
        xnat.init_maps();

        xnat.setup_grpc();

        xnat.event_loop();

    } catch (std::string &e) {
        err("%s", e.c_str());
    }

    try {
        if (config.rm_flag) {
            xnat.unpin_maps();
            xnat.detach_bpf_progs();
        }
    } catch (std::string &e) {
        err("%s", e.c_str());
    }
    return SUCCESS;
}
