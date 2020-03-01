#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <errno.h>
#include <unistd.h>

#include "xnat_dump.h"
#include "message.h"
#include "getopt_long.h"

void
usage(void) {
    printf("Usage: ./xnat_dump [options] (root permission)\n");
    printf("\n");
    printf("  Options:\n");
    printf("    --filename, -f: pcap file name\n");
    printf("    --quiet, -q: disable hex dump stdout\n");
    printf("    --help,    -h: help\n");
    printf("\n");
}
const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"filename", required_argument, NULL, 'f'},
    {"quiet", no_argument, NULL, 'q'},
};

const char short_options[] = "f:qh";

int
set_config(int argc, char *const argv[], struct config &cfg) {
    cfg.verbose = 1;

    int has_filename = 0;
    int c;
    while ((c = gopt.getopt_long(
                argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'f':
                cfg.dumpfile = gopt.opt_arg;
                has_filename = 1;
                break;
            case 'q':
                cfg.verbose = 0;
                break;
            case 'h':
                usage();
                exit(1);
            default:
                usage();
                exit(1);
        }
    }

    if (has_filename == 0) {
        cfg.dumpfile = "/tmp/xnat.pcap";
    }

    cfg.subdir         = "xnat";
    cfg.map_name       = "pcap_map";
    cfg.pin_basedir    = "/sys/fs/bpf";
    cfg.map_pin_dir    = cfg.pin_basedir + "/" + cfg.subdir;
    cfg.server_address = "localhost:10000";

    return SUCCESS;
}

int
main(int argc, char *const argv[]) {
    struct rlimit lck_mem = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &lck_mem)) {
        err("Can't change limit for locked memory");
        return ERROR;
    }

    struct config cfg;

    cfg.nr_cpus = bpf_num_possible_cpus();

    set_config(argc, argv, cfg);

    info("dump filename (%s)", cfg.dumpfile.c_str());

    static class dump dump;
    try {
        dump.set_config(cfg);
        dump.set_signal();
        dump.open_bpf_map_file(cfg.map_pin_dir, cfg.map_name);
        dump.test_bpf_perf_event();
        dump.perf_event_mmap();
        dump.open_pcap();
        dump.setup_grpc();
        dump.enable_dump_mode();
        dump.perf_event_poller_multi();

    } catch (std::string &e) {
        err("%s", e.c_str());
    }

    dump.disable_dump_mode();

    dump.print_result();
    return SUCCESS;
}
