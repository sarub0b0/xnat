#pragma once

#include <string>
#include <cstdint>

#include <bpf/libbpf.h>

struct config {
    struct bpf_prog_load_attr prog_load_attr;
    uint32_t xdp_flags;
    std::string ingress_ifname;
    std::string ingress_progsec;
    std::string egress_ifname;
    std::string egress_progsec;
    std::string load_obj_name;
    std::string map_pin_dir;
    std::string pin_basedir;
    std::string listen_address;
    int rm_flag;
    uint32_t nr_cpus;
};

void
print_config(struct config &cfg) {

    printf("");
}
