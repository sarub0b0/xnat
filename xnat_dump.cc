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
main(int argc, char *const argv[]) {

    struct bpf_map_info ingress_info = {0};
    struct bpf_map_info egress_info  = {0};
    struct bpf_map_info pcap_info    = {0};
    std::string filename;
    std::string pin_dir;
    std::string ingress_prog_map_pin_dir;
    std::string egress_prog_map_pin_dir;
    int map_fd;
    int ingress_prog_fd;
    int egress_prog_fd;
    int numcpus = bpf_num_possible_cpus();
    int err;

    filename = default_filename;

    enum bpf_perf_event_ret ret;

    pin_dir = pin_basedir + "/" + subdir;

    int c;
    while ((c = gopt.getopt_long(
                argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'f':
                filename = gopt.opt_arg;
                break;
            case 'q':
                verbose = 0;
                break;
            case 'h':
                usage();
                exit(1);
            default:
                usage();
                exit(1);
        }
    }
    if (signal(SIGINT, sig_handler) || signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        err("signal");
        return 1;
    }

    info("dump filename (%s)", filename.c_str());

    pin_dir = pin_basedir + "/dump";

    ingress_prog_map_pin_dir = pin_basedir + "/" + subdir;
    egress_prog_map_pin_dir  = pin_basedir + "/" + subdir;

    struct bpf_prog_info ingress_prog_info = {0};
    struct bpf_prog_info egress_prog_info  = {0};
    struct bpf_object *ingress_obj;
    struct bpf_object *egress_obj;
    struct bpf_program *ingress_program;
    struct bpf_program *egress_program;

    std::string ingress_prog_name = "dump_ingress.o";
    std::string ingress_progsec   = "dump/ingress";
    std::string egress_prog_name  = "dump_egress.o";
    std::string egress_progsec    = "dump/egress";

    int ingress_progsec_fd;
    int egress_progsec_fd;
    err = open_bpf_prog_file(ingress_prog_name,
                             ingress_progsec,
                             &ingress_obj,
                             &ingress_program,
                             &ingress_prog_fd,
                             &ingress_progsec_fd);
    if (err < 0) {
        err("Cannot open %s", pin_dir.c_str());
        return 1;
    }

    err = pin_maps_in_bpf_object(ingress_obj, pin_dir.c_str());
    if (err > 0) {
        return EXIT_FAIL_BPF;
    }

    std::string ingress_prog_array_map = "ingress_prog_map";

    int ingress_prog_map_fd;

    err = open_bpf_prog_file(egress_prog_name,
                             egress_progsec,
                             &egress_obj,
                             &egress_program,
                             &egress_prog_fd,
                             &egress_progsec_fd);
    if (err < 0) {
        err("Cannot open %s", pin_dir.c_str());
        return 1;
    }

    ingress_prog_map_fd = open_bpf_map_file(
        ingress_prog_map_pin_dir, ingress_prog_array_map, &ingress_info);
    if (ingress_prog_map_fd < 0) {
        err("Cannot open %s", ingress_prog_map_pin_dir.c_str());
        return 1;
    }

    err = attach(ingress_progsec_fd, ingress_prog_map_fd);
    if (err < 0) {
        err("Failed attach dump_ingress");
        return 1;
    }

    std::string egress_prog_array_map = "egress_prog_map";
    int egress_prog_map_fd;
    egress_prog_map_fd = open_bpf_map_file(
        egress_prog_map_pin_dir, egress_prog_array_map, &egress_info);
    if (egress_prog_map_fd < 0) {
        err("Cannot open %s", egress_prog_map_pin_dir.c_str());
        return 1;
    }

    err = attach(egress_progsec_fd, egress_prog_map_fd);
    if (err < 0) {
        err("Failed attach dump_ingress");
        return 1;
    }

    map_fd = open_bpf_map_file(pin_dir, map_name, &pcap_info);
    if (map_fd < 0) {
        err("Cannot open %s", pin_dir.c_str());
        return 1;
    }

    test_bpf_perf_event(map_fd, numcpus);

    for (int i = 0; i < numcpus; i++)
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) return 1;

    pd = nullptr;

    pd = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pd) {
        err("pcap_open_dead failed");
        goto out;
    }

    pdumper = nullptr;

    pdumper = pcap_dump_open(pd, filename.c_str());
    if (!pdumper) {
        err("pcap_dump_open failed");
        goto out;
    }

    ret = perf_event_poller_multi(
        pmu_fds, headers, numcpus, print_bpf_output, &done);

    pcap_dump_close(pdumper);
    pcap_close(pd);

    err = detach(ingress_progsec_fd, ingress_prog_map_fd);
    if (err < 0) {
        err("Failed detach dump_ingress");
    }
    err = detach(egress_progsec_fd, egress_prog_map_fd);
    if (err < 0) {
        err("Failed detach dump_ingress");
    }

out:
    info("");
    info("%u packet samples stored in %s", pcap_pkts, filename.c_str());
    return ret;
}
