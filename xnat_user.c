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
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "stats.h"
#include "message.h"
#include "utils.h"
#include "nat.h"
#include "ifinfo.h"

const char *pin_basedir        = "/sys/fs/bpf";
const char *tx_map_name        = "tx_map";
const char *redirect_map_name  = "redirect_params";
const char *nat_map_name       = "nat_map";
const char *port_pool_map_name = "port_pool_map";
const char *freelist_map_name  = "freelist_map";
const char *if_map_name        = "if_map";

const char *i_ifname = "xnat0";
const char *e_ifname = "xnat1";

const char *sub_dir = "xnat";

int register_ifinfo(int map_fd, int ifindex, const char *ifname) {

    int err;

    int sock;
    struct ifreq ifreq;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    strcpy(ifreq.ifr_name, ifname);

    err = ioctl(sock, SIOCGIFHWADDR, &ifreq);
    if (err < 0) {
        close(sock);
        return -1;
    }

    struct ifinfo info;
    memcpy(info.mac, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

    err = ioctl(sock, SIOCGIFADDR, &ifreq);
    if (err < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in saddr;
    memcpy(&saddr, &ifreq.ifr_addr, sizeof(saddr));

    memcpy(&info.ip, &saddr.sin_addr, 4);

    info("ifindex(%d) addr(0x%x) mac(%02x:%02x:%02x:%02x:%02x:%02x)",
         ifindex,
         ntohl(info.ip),
         // (uint32_t) ifreq.ifr_addr.sa_data,
         info.mac[0],
         info.mac[1],
         info.mac[2],
         info.mac[3],
         info.mac[4],
         info.mac[5]);

    bpf_map_update_elem(map_fd, &ifindex, &info, 0);

    return 0;
}

int main(int argc, char const *argv[]) {

    char pin_dir[PATH_MAX];
    struct bpf_map_info info = {0};
    int tx_map_fd;
    int redirect_map_fd;
    int nat_map_fd;
    int port_pool_map_fd;
    int freelist_map_fd;
    int if_map_fd;
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

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, sub_dir);
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

    nat_map_fd = open_bpf_map_file(pin_dir, nat_map_name, &info);
    if (nat_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", nat_map_name);
        return EXIT_FAIL_BPF;
    }

    if_map_fd = open_bpf_map_file(pin_dir, if_map_name, &info);
    if (if_map_fd < 0) {
        fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", if_map_name);
        return EXIT_FAIL_BPF;
    }

    if (if_map_fd) {
        register_ifinfo(if_map_fd, i_ifindex, i_ifname);
        register_ifinfo(if_map_fd, e_ifindex, e_ifname);
    }

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
        uint16_t v   = 0;
        uint16_t key = 0;
        for (uint16_t i = 0; i < 65535; i++) {
            key = htons(i);
            bpf_map_update_elem(port_pool_map_fd, &key, &v, BPF_ANY);
        }
        info("\tDone");
    }

    if (freelist_map_fd) {
        info(" - Initialize freelist map");
        uint16_t key = 0;
        for (uint16_t i = 1024; i < 61024; i++) {
            key = htons(i);
            bpf_map_update_elem(freelist_map_fd, NULL, &key, 0);
        }
        info("\tDone");
    }

    info("Check port pool map");
    int err;
    while (1) {
        uint16_t port;
        struct nat_table nt     = {0};
        struct nm_k nt_key      = {0};
        struct nm_k nt_prev_key = {0};

        info("");
        info("==== port pool ====");
        for (uint16_t i = 1024; i < 61024; i++) {
            i = htons(i);
            if ((bpf_map_lookup_elem(port_pool_map_fd, &i, &port)) != 0) {
                err("bpf_map_lookup_elem failed");
            } else {
                if (port > 0) {
                    info("\tPort %u -> %u", ntohs(i), ntohs(port));
                }
            }
            i = ntohs(i);
        }

        err = bpf_map_get_next_key(nat_map_fd, NULL, &nt_key);
        if (err < 0) {
            err("bpf_map_get_next_key failed");
        } else {

            err = bpf_map_lookup_elem(nat_map_fd, &nt_key, &nt);
            if (err < 0) {
                err("bpf_map_lookup_elem failed");
            } else {
                while (bpf_map_get_next_key(
                           nat_map_fd, &nt_prev_key, &nt_key) == 0) {
                    err = bpf_map_lookup_elem(nat_map_fd, &nt_key, &nt);
                    if (err < 0) {
                        err("bpf_map_lookup_elem failed");
                    } else {
                        info("");
                        info("==== nat table ====");
                        info("\tkey addr(0x%08x) port(%d)",
                             ntohl(nt_key.addr),
                             htons(nt_key.port));
                        info("\tingress_ifindex(%d)", nt.ingress_ifindex);
                        info("\tegress_ifindex(%d)", nt.egress_ifindex);
                        info("\tsport(%d)", ntohs(nt.sport));
                        info("\tdport(%d)", ntohs(nt.dport));
                        info("\tsaddr(0x%08x)", ntohl(nt.saddr));
                        info("\tdaddr(0x%08x)", ntohl(nt.daddr));
                        info("\tproto(%d)", nt.proto);
                        info("\tnew addr(0x%08x)", ntohl(nt.new_addr));
                        info("\tnew port(%d)", ntohs(nt.new_port));
                        info("\tsrc eth(%02x:%02x:%02x:%02x:%02x:%02x)",
                             nt.seth[0],
                             nt.seth[1],
                             nt.seth[2],
                             nt.seth[3],
                             nt.seth[4],
                             nt.seth[5]);
                        info("\tdst eth(%02x:%02x:%02x:%02x:%02x:%02x)",
                             nt.deth[0],
                             nt.deth[1],
                             nt.deth[2],
                             nt.deth[3],
                             nt.deth[4],
                             nt.deth[5]);
                    }

                    nt_prev_key = nt_key;
                }
            }
        }

        sleep(1);
    }

    return EXIT_OK;
}
