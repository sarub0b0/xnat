#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <locale.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include <grpcpp/grpcpp.h>

#include "stats.h"
#include "message.h"
#include "utils.h"
#include "nat.h"
#include "ifinfo.h"
#include "prog.h"

#include "adapter.h"
#include "config.h"

#include "xnat.grpc.pb.h"

#define EV_MAX 16

namespace xnat {

class xnat;

class XnatServiceImpl final : public XnatService::Service {
   public:
    XnatServiceImpl() {
    }
    ~XnatServiceImpl() {
    }
    ::grpc::Status EnableDumpMode(::grpc::ServerContext context,
                                  const Empty *request,
                                  Bool *response);

    ::grpc::Status DisableDumpMode(::grpc::ServerContext context,
                                   const Empty *empty,
                                   Bool *boolean);

    ::grpc::Status EnableStatusMode(::grpc::ServerContext context,
                                    const Empty *empty,
                                    Bool *boolean);

    ::grpc::Status DisableStatusMode(::grpc::ServerContext context,
                                     const Empty *empty,
                                     Bool *boolean);

    void
    set_xnat(class xnat *xnat) {
        xnat_ = xnat;
    };

   private:
    class xnat *xnat_;
};

::grpc::Status
XnatServiceImpl::EnableDumpMode(::grpc::ServerContext context,
                                const Empty *empty,
                                Bool *boolean) {
    boolean->set_success(true);
    return ::grpc::Status::OK;
}

::grpc::Status
XnatServiceImpl::DisableDumpMode(::grpc::ServerContext context,
                                 const Empty *empty,
                                 Bool *boolean) {

    boolean->set_success(true);
    return ::grpc::Status::OK;
}
::grpc::Status
XnatServiceImpl::EnableStatusMode(::grpc::ServerContext context,
                                  const Empty *empty,
                                  Bool *boolean) {

    boolean->set_success(true);
    return ::grpc::Status::OK;
}
::grpc::Status
XnatServiceImpl::DisableStatusMode(::grpc::ServerContext context,
                                   const Empty *empty,
                                   Bool *boolean) {

    boolean->set_success(true);
    return ::grpc::Status::OK;
}

class xnat {
   public:
    xnat(const struct config &config) : config_(config) {
    }
    ~xnat() {
    }

    int init();
    int load_bpf_progs();
    int attach_bpf_progs();
    int detach_bpf_progs();
    int pin_maps();
    int unpin_maps();
    int set_xnat_to_prog_array();
    int event_loop();
    int init_maps();
    int setup_grpc();
    int run_grpc_server();

   private:
    int _epoll_add(int ep, int fd, uintptr_t ptr);
    int _set_signal();
    int _register_ifinfo(int fd, const char *ifname, uint32_t ifindex);
    int _update_prog_array(const std::string &map_name,
                           const std::string &progsec,
                           int index);
    int _event_poll();

    int _init_if_map();
    int _init_tx_map();
    int _init_port_pool();
    int _init_freelist();

    void _print_nat_table();

    class adapter adapter_;
    struct config config_;
    uint32_t ingress_ifindex_;
    uint32_t egress_ifindex_;
    sigset_t sigset_;

    std::string listen_address_;

    ::grpc::ServerBuilder builder_;
    XnatServiceImpl xnat_service_;
};

int
xnat::setup_grpc() {

    listen_address_ = config_.listen_address;

    builder_.AddListeningPort(listen_address_, ::grpc::InsecureServerCredentials());
    builder_.RegisterService(&xnat_service_);

    return SUCCESS;
}

int
xnat::run_grpc_server() {
    std::unique_ptr<::grpc::Server> server(builder_.BuildAndStart());

    info("Server listening on %s", listen_address_.c_str());

    server->Wait();

    return SUCCESS;
}

int
xnat::_epoll_add(int ep, int fd, uintptr_t ptr) {
    int err;
    struct epoll_event ev = {};

    ev.events = EPOLLIN;
    if (ptr == 0)
        ev.data.fd = fd;
    else
        ev.data.u64 = ptr;

    err = epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    if (err < 0) {
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::_set_signal() {
    int ret;
    sigemptyset(&sigset_);

    ret = sigaddset(&sigset_, SIGUSR1);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }
    ret = sigaddset(&sigset_, SIGUSR2);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }
    ret = sigaddset(&sigset_, SIGHUP);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }

    ret = sigaddset(&sigset_, SIGINT);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }

    ret = sigaddset(&sigset_, SIGTERM);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }

    ret = pthread_sigmask(SIG_BLOCK, &sigset_, NULL);
    if (ret == -1) {
        perror("sigaddset");
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::load_bpf_progs() {
    info("Load bpf program %s", config_.load_obj_name.c_str());
    int err;
    err = adapter_.load_bpf_prog(config_.load_obj_name, config_.prog_load_attr);
    if (err < 0) {
        throw std::string("failed load_bpf_prog " + config_.load_obj_name);
    }
    return SUCCESS;
}

int
xnat::attach_bpf_progs() {

    ingress_ifindex_ = adapter_.attach_bpf_prog(
        config_.ingress_progsec, config_.ingress_ifname, config_.xdp_flags);
    if (ingress_ifindex_ < 0) {
        throw std::string("failed attach_bpf_prog to ingress " +
                          config_.ingress_ifname);
    }
    info("Attach to interface %s:id(%d)",
         config_.ingress_ifname.c_str(),
         ingress_ifindex_);

    egress_ifindex_ = adapter_.attach_bpf_prog(
        config_.egress_progsec, config_.egress_ifname, config_.xdp_flags);
    if (egress_ifindex_ < 0) {
        throw std::string("failed attach_bpf_prog to egress " +
                          config_.egress_ifname);
    }
    info("Attach to interface %s:id(%d)",
         config_.egress_ifname.c_str(),
         egress_ifindex_);

    return SUCCESS;
}

int
xnat::detach_bpf_progs() {
    int err;
    err = adapter_.detach_bpf_prpg(
        -1, ingress_ifindex_, XDP_FLAGS_UPDATE_IF_NOEXIST | config_.xdp_flags);
    if (err < 0) {
        throw std::string("failed detach_bpf_prpg to ingress (" +
                          std::to_string(ingress_ifindex_) + ")");
    }
    info("Detach to interface %s:id(%d)",
         config_.ingress_ifname.c_str(),
         ingress_ifindex_);

    err = adapter_.detach_bpf_prpg(
        -1, egress_ifindex_, XDP_FLAGS_UPDATE_IF_NOEXIST | config_.xdp_flags);
    if (err < 0) {
        throw std::string("failed detach_bpf_prpg to egress (" +
                          std::to_string(egress_ifindex_) + ")");
    }
    info("Detach to interface %s:id(%d)",
         config_.egress_ifname.c_str(),
         egress_ifindex_);

    return SUCCESS;
}

int
xnat::pin_maps() {
    int err;

    info("Pinning maps in %s", config_.map_pin_dir.c_str());

    err = adapter_.pin_maps(config_.map_pin_dir);
    if (err < 0) {
        throw std::string("failed to pin maps - " + config_.map_pin_dir);
    }

    return SUCCESS;
}

int
xnat::unpin_maps() {
    int err;

    info("Unpinning maps in %s", config_.map_pin_dir.c_str());

    err = adapter_.unpin_maps(config_.load_obj_name, config_.map_pin_dir);
    if (err < 0) {
        throw std::string("failed to pin maps - " + config_.map_pin_dir);
    }

    return SUCCESS;
}

int
xnat::_update_prog_array(const std::string &map_name,
                         const std::string &progsec,
                         int index) {

    int err;
    int map_fd, prog_fd;

    map_fd  = adapter_.get_map_fd_by_name(map_name);
    prog_fd = adapter_.get_prog_fd_by_name(progsec);

    err = adapter_.map_update_element(map_fd,
                                      static_cast<void *>(&index),
                                      static_cast<void *>(&prog_fd),
                                      BPF_ANY);
    if (err) {
        err("failed update %s:%s", progsec.c_str(), map_name.c_str());
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::set_xnat_to_prog_array() {
    int err;

    std::string map_name;
    std::string prog_name;
    int index;

    index     = 0;
    map_name  = "ingress_prog_map";
    prog_name = "xnat/nat/ingress";

    err = _update_prog_array(map_name, prog_name, index);
    if (err) {
        throw std::string("failed update " + map_name);
    }

    info(
        "Update ingress prog array map index(%d):%s", index, prog_name.c_str());

    map_name  = "egress_prog_map";
    prog_name = "xnat/nat/egress";

    err = _update_prog_array(map_name, prog_name, index);
    if (err) {
        throw std::string("failed update " + map_name);
    }

    info(
        "Update ingress prog array map index(%d):%s", index, prog_name.c_str());

    return SUCCESS;
}

void
xnat::_print_nat_table() {
    int err;
    uint16_t port;
    struct nat_info nt      = {};
    struct nm_k nt_key      = {};
    struct nm_k nt_prev_key = {};

    int port_pool_map_fd = adapter_.get_map_fd_by_name("port_pool_map");
    int nat_map_fd       = adapter_.get_map_fd_by_name("nat_map");

    info("");
    info("==== port pool ====");
    for (uint16_t i = 1024; i < 61024; i++) {
        i = htons(i);
        if ((adapter_.map_lookup_element(port_pool_map_fd, &i, &port)) != 0) {
            err("bpf_map_lookup_elem failed");
        } else {
            if (port > 0) {
                info("\tPort %u -> %u", ntohs(i), ntohs(port));
            }
        }
        i = ntohs(i);
    }

    err = adapter_.map_get_next_key(nat_map_fd, NULL, &nt_key);
    if (err < 0) {
        err("bpf_map_get_next_key failed");
    } else {
        err = adapter_.map_lookup_element(nat_map_fd, &nt_key, &nt);
        if (err < 0) {
            err("bpf_map_lookup_elem failed");
        } else {
            while (adapter_.map_get_next_key(
                       nat_map_fd, &nt_prev_key, &nt_key) == 0) {
                err = adapter_.map_lookup_element(nat_map_fd, &nt_key, &nt);
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
}

int
xnat::_event_poll() {
    int err;
    int ep_fd;
    int sig_fd;
    ep_fd = epoll_create(EV_MAX);

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    sig_fd = signalfd(-1, &sigset, 0);

    err = _epoll_add(ep_fd, sig_fd, 0);
    if (err < 0) {
        err("failed _epoll_add");
        return ERROR;
    }

    struct epoll_event ev[EV_MAX];

    while (1) {
        err = epoll_wait(ep_fd, ev, EV_MAX, 5000);
        if (err < 0) {
            err("epoll ERROR");
            ;
        } else if (err == 0) {
            _print_nat_table();
            ;
        } else {
            // check event
            for (int i = 0; i < err; i++) {
                if (ev[i].data.fd == sig_fd) {
                    struct signalfd_siginfo s_buf;
                    err = read(sig_fd, &s_buf, sizeof(s_buf));
                    info("Signal handled");
                    return SUCCESS;
                } else {
                    ;
                }
            }
        }
    }

    return SUCCESS;
}

int
xnat::event_loop() {

    info("Event loop");

    int err;

    err = _event_poll();
    if (err < 0) {
        throw "Event ERROR";
    }

    info("epoll finished");
    return SUCCESS;
}

int
xnat::init_maps() {
    info("Initialize maps");
    info(" - Initialize if_map");
    if (_init_if_map() < 0) return ERROR;

    info(" - Initialize tx_map");
    if (_init_tx_map() < 0) return ERROR;

    info(" - Initialize port_pool_map");
    if (_init_port_pool() < 0) return ERROR;

    info(" - Initialize freelist_map");
    if (_init_freelist() < 0) return ERROR;

    return SUCCESS;
}

int
xnat::_register_ifinfo(int fd, const char *ifname, uint32_t ifindex) {
    int err;

    int sock;
    struct ifreq ifr;
    struct ifinfo info;
    struct sockaddr_in saddr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return ERROR;
    }

    strcpy(ifr.ifr_name, ifname);

    err = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (err < 0) {
        close(sock);
        return ERROR;
    }

    memcpy(info.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    err = ioctl(sock, SIOCGIFADDR, &ifr);
    if (err < 0) {
        close(sock);
        return ERROR;
    }

    memcpy(&saddr, &ifr.ifr_addr, sizeof(saddr));

    memcpy(&info.ip, &saddr.sin_addr, 4);
    info(
        "   - ifindex(%d) addr(0x%x/%u.%u.%u.%u) "
        "mac(%02x:%02x:%02x:%02x:%02x:%02x)",
        ifindex,
        ntohl(info.ip),
        info.ip & 0xff,
        (info.ip >> 8) & 0xff,
        (info.ip >> 16) & 0xff,
        (info.ip >> 24) & 0xff,
        info.mac[0],
        info.mac[1],
        info.mac[2],
        info.mac[3],
        info.mac[4],
        info.mac[5]);

    err = adapter_.map_update_element(fd, &ifindex, &info, BPF_ANY);
    if (err) {
        err("Can't register %s:%d", ifname, ifindex);
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::_init_if_map() {
    int err;
    int map_fd;

    map_fd = adapter_.get_map_fd_by_name("if_map");

    err = _register_ifinfo(
        map_fd, config_.ingress_ifname.c_str(), ingress_ifindex_);
    if (err < 0) {
        throw std::string("Failed register ingress ifinfo " +
                          config_.ingress_ifname);
    }

    err = _register_ifinfo(
        map_fd, config_.egress_ifname.c_str(), egress_ifindex_);
    if (err < 0) {
        throw std::string("Failed register egress ifinfo " +
                          config_.egress_ifname);
    }

    return SUCCESS;
}

int
xnat::_init_tx_map() {
    int err;
    int map_fd;

    map_fd = adapter_.get_map_fd_by_name("tx_map");

    err = adapter_.map_update_element(
        map_fd, &ingress_ifindex_, &egress_ifindex_, BPF_ANY);
    if (err < 0) {
        throw "Failed update tx_map";
    }

    err = adapter_.map_update_element(
        map_fd, &egress_ifindex_, &ingress_ifindex_, BPF_ANY);
    if (err < 0) {
        throw "Failed update tx_map";
    }

    info("   - redirect from if(%s:%d) -> if(%s:%d)",
         config_.ingress_ifname.c_str(),
         ingress_ifindex_,
         config_.egress_ifname.c_str(),
         egress_ifindex_);

    return SUCCESS;
}

int
xnat::_init_port_pool() {
    int err;

    int fd       = adapter_.get_map_fd_by_name("port_pool_map");
    uint16_t v   = 0;
    uint16_t key = 0;
    for (uint16_t i = 0; i < 65535; i++) {
        key = htons(i);
        err = adapter_.map_update_element(fd, &key, &v, BPF_ANY);
        if (err) {
            err("failed update port_pool_map");
            return ERROR;
        }
    }

    return SUCCESS;
}

int
xnat::_init_freelist() {
    int err;

    int fd = adapter_.get_map_fd_by_name("freelist_map");

    uint16_t key = 0;
    for (uint16_t i = 1024; i < 61024; i++) {
        key = htons(i);
        err = adapter_.map_update_element(fd, NULL, &key, 0);
        if (err) {
            err("failed update freelist_map");
            return ERROR;
        }
    }

    return SUCCESS;
}

}; // namespace xnat
