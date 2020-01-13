#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <locale.h>

#include "stats.h"
#include "message.h"
#include "utils.h"

const char *pin_basedir        = "/sys/fs/bpf";
const char *tx_map_name        = "tx_map";
const char *redirect_map_name  = "redirect_params";
const char *nat_map_name       = "nat_map";
const char *port_pool_map_name = "port_pool_map";
const char *freelist_map_name  = "freelist_map";

const char *i_ifname = "xnat0";
const char *e_ifname = "xnat1";

int main(int argc, char const *argv[]) {

    char pin_dir[PATH_MAX];
    struct bpf_map_info info = {0};
    int tx_map_fd;
    int redirect_map_fd;
    int nat_map_fd;
    int port_pool_map_fd;
    int freelist_map_fd;
    int len;

    uint32_t i_ifindex, e_ifindex;

    i_ifindex = if_nametoindex(i_ifname);
    e_ifindex = if_nametoindex(e_ifname);

    if (!i_ifindex) {
        err("Unknown interface %s", i_ifname);
        return EXIT_FAIL_OPTION;
    }

    if (!e_ifindex) {
        err("Unknown interface %s", e_ifname);
        return EXIT_FAIL_OPTION;
    }

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "xnat0");
    if (len < 0) {
        err("creating pin dirname");
        return EXIT_FAIL_OPTION;
    }

    tx_map_fd = open_bpf_map_file(pin_dir, tx_map_name, &info);
    if (tx_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", tx_map_name);
        return EXIT_FAIL_BPF;
    }

    redirect_map_fd = open_bpf_map_file(pin_dir, redirect_map_name, &info);
    if (redirect_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", redirect_map_name);
        return EXIT_FAIL_BPF;
    }

    port_pool_map_fd = open_bpf_map_file(pin_dir, port_pool_map_name, &info);
    if (port_pool_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", port_pool_map_name);
        return EXIT_FAIL_BPF;
    }

    freelist_map_fd = open_bpf_map_file(pin_dir, freelist_map_name, &info);
    if (freelist_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", freelist_map_name);
        return EXIT_FAIL_BPF;
    }

    // nat_map_fd = open_bpf_map_file(pin_dir, nat_map_name, &info);
    // if (nat_map_fd < 0) {
    //     fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", nat_map_name);
    //     return EXIT_FAIL_BPF;
    // }
    //
    if (redirect_map_fd) {
        info(" - Initialize redirect map");
        unsigned char dst[ETH_ALEN] = {
            0x3e,
            0x86,
            0xde,
            0xf6,
            0x2e,
            0xc7,
        };

        unsigned char src[ETH_ALEN] = {
            0x96,
            0xa2,
            0x7e,
            0xa4,
            0xdf,
            0x45,
        };

        unsigned char engress_source[ETH_ALEN] = {
            0xa2,
            0x2f,
            0x68,
            0x6c,
            0x53,
            0xe1,
        };

        bpf_map_update_elem(redirect_map_fd, &src, &dst, 0);

        bpf_map_update_elem(redirect_map_fd, &dst, &engress_source, 0);
        info("\tDone");
    }

    if (tx_map_fd) {
        info(" - Initialize tx map");
        bpf_map_update_elem(tx_map_fd, &i_ifindex, &e_ifindex, 0);
        bpf_map_update_elem(tx_map_fd, &e_ifindex, &i_ifindex, 0);
        info("redirect from if(%s:%d) -> if(%s:%d)",
             i_ifname,
             i_ifindex,
             e_ifname,
             e_ifindex);
        info("\tDone");
    }

    uint32_t nr_cpus = bpf_num_possible_cpus();
    if (port_pool_map_fd) {
        info(" - Initialize port-pool map");
        uint16_t v = 0;
        for (uint16_t i = 1024; i < 61024; i++) {
            bpf_map_update_elem(port_pool_map_fd, &i, &v, BPF_ANY);
        }
        info("\tDone");
    }

    if (freelist_map_fd) {
        info(" - Initialize freelist map");
        for (uint16_t i = 1024; i < 61024; i++) {
            bpf_map_update_elem(freelist_map_fd, NULL, &i, 0);
        }
        info("\tDone");
    }

    info("Check port pool map");
    uint16_t port;
    while (1) {
        for (uint16_t i = 1024; i < 61024; i++) {
            if ((bpf_map_lookup_elem(port_pool_map_fd, &i, &port)) != 0) {
                err("bpf_map_lookup_elem failed");
            } else {
                if (port > 0) {
                    info("Port %u -> %u", i, port);
                }
            }
        }
        sleep(1);
    }

    return EXIT_OK;
}
