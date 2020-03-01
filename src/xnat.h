#pragma once

#define _GNU_SOURCE 1
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include <asm/types.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/perf_event.h>
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
#include <sys/syscall.h>
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
#include "network_controll.h"

#include "lpm_trie.h"

#include "xnat.grpc.pb.h"

#define EV_MAX 16
#define MAX_CPUS 128

namespace xnat {
using namespace grpc;

class xnat final : public XnatService::Service {

   public:
    xnat(const struct config &config)
        : net_ctrl_(config.ingress_ifname, config.egress_ifname),
          config_(config) {
    }
    ~xnat() {
    }

    Status GetIngressInfo(ServerContext *context,
                          const Empty *request,
                          Iface *response) override;
    Status GetEgressInfo(ServerContext *context,
                         const Empty *request,
                         Iface *response) override;

    Status EnableDumpMode(ServerContext *context,
                          const Empty *request,
                          Bool *response) override;

    Status DisableDumpMode(ServerContext *context,
                           const Empty *request,
                           Bool *response) override;

    Status EnableStatsMode(ServerContext *context,
                           const Empty *request,
                           Bool *response) override;

    Status DisableStatsMode(ServerContext *context,
                            const Empty *request,
                            Bool *response) override;

    Status AddVip(ServerContext *context,
                  const Vip *request,
                  Bool *response) override;
    Status DelVip(ServerContext *context,
                  const Vip *request,
                  Bool *response) override;

    Status AddVlanIface(ServerContext *context,
                        const Iface *request,
                        Bool *response) override;
    Status DelVlanIface(ServerContext *context,
                        const Iface *request,
                        Bool *response) override;

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

    static void *run_grpc_server(void *args);

   private:
    int _epoll_add(int ep, int fd, uintptr_t ptr);
    int _set_signal();
    int _register_ifinfo(int fd, const char *ifname, uint32_t ifindex);
    int _update_prog_array(const std::string &map_name,
                           const std::string &progsec,
                           int index);
    int _event_poll();
    int _enable_dump_mode();
    int _disable_dump_mode();

    int _init_ifinfo_map();
    int _init_tx_map();
    int _init_port_pool();
    int _init_freelist();
    int _init_vip_table();
    int _init_lpm_trie();

    void _print_nat_table();

    class network_controll net_ctrl_;

    class adapter adapter_;
    struct config config_;
    uint32_t ingress_ifindex_;
    uint32_t egress_ifindex_;
    sigset_t sigset_;

    int ingress_prog_array_fd_;
    int ingress_dump_fd_;
    int ingress_nat_fd_;

    int egress_prog_array_fd_;
    int egress_dump_fd_;
    int egress_nat_fd_;

    int pmu_fds_[MAX_CPUS];

    static std::string listen_address_;

    static ServerBuilder builder_;
};

std::string xnat::listen_address_ = "0.0.0.0:0";
ServerBuilder xnat::builder_;

Status
xnat::GetIngressInfo(ServerContext *context,
                     const Empty *request,
                     Iface *response) {

    response->set_name(config_.ingress_ifname);
    response->set_vid(0);

    return Status::OK;
}

Status
xnat::GetEgressInfo(ServerContext *context,
                    const Empty *request,
                    Iface *response) {

    response->set_name(config_.egress_ifname);
    response->set_vid(0);

    return Status::OK;
}

Status
xnat::EnableDumpMode(ServerContext *context,
                     const Empty *request,
                     Bool *response) {
    info("Call EnableDumpMode");

    if (_enable_dump_mode() < 0) {
        response->set_success(false);
    } else {
        response->set_success(true);
    }

    return Status::OK;
}

Status
xnat::DisableDumpMode(ServerContext *context,
                      const Empty *request,
                      Bool *response) {

    info("Call DisableDumpMode");
    if (_disable_dump_mode() < 0) {
        response->set_success(false);
    }
    response->set_success(true);
    return Status::OK;
}

Status
xnat::EnableStatsMode(ServerContext *context,
                      const Empty *request,
                      Bool *response) {

    info("Call EnableStatsMode");

    response->set_success(true);
    return Status::OK;
}

Status
xnat::DisableStatsMode(ServerContext *context,
                       const Empty *request,
                       Bool *response) {

    info("Call DisableStatsMode");
    response->set_success(true);
    return Status::OK;
}

Status
xnat::AddVip(ServerContext *context, const Vip *request, Bool *response) {

    const Iface &iface = request->iface();
    const Addr &addr   = request->addr();
    const Type &type   = request->type();
    int fd             = 0;

    response->set_success(true);

    if (net_ctrl_.add_vip(iface.name(), iface.vid(), addr.addr()) < 0) {
        response->set_success(false);
    }

    if (type == INGRESS) {
        info("update ingress vip table");
        fd = adapter_.get_map_fd_by_name("ingress_vip_table");
    } else if (type == EGRESS) {
        info("update egress vip table");
        fd = adapter_.get_map_fd_by_name("egress_vip_table");
    }

    __be32 ip;
    __u32 vid;

    vid = iface.vid();

    int last = addr.addr().find_first_of("/");
    std::string str_addr(addr.addr(), 0, last);

    inet_pton(AF_INET, str_addr.c_str(), &ip);

    ip = htonl(ip);

    info("vid(%d) ip(0x%x)", vid, ip);

    adapter_.map_update_element(fd, &vid, &ip, BPF_ANY);

    return Status::OK;
}

Status
xnat::DelVip(ServerContext *context, const Vip *request, Bool *response) {
    return Status::OK;
}

Status
xnat::AddVlanIface(ServerContext *context,
                   const Iface *request,
                   Bool *response) {
    return Status::OK;
}
Status
xnat::DelVlanIface(ServerContext *context,
                   const Iface *request,
                   Bool *response) {

    response->set_success(true);

    if (net_ctrl_.del_vlan_iface(request->name()) < 0) {
        response->set_success(false);
    }

    int fd    = 0;
    __be32 ip = 0;
    __u32 vid = 0;

    if (request->type() == INGRESS) {
        fd = adapter_.get_map_fd_by_name("ingress_vip_table");
    } else if (request->type() == EGRESS) {
        fd = adapter_.get_map_fd_by_name("egress_vip_table");
    }

    vid = request->vid();

    if (adapter_.map_update_element(fd, &vid, &ip, BPF_ANY)) {
        err("failed delete %s vip_table vid(%d)",
            Type_Name(request->type()).c_str(),
            vid);
    }
    info(
        "Delete %s vip_table vid(%d)", Type_Name(request->type()).c_str(), vid);

    return Status::OK;
}

int
xnat::_enable_dump_mode() {

    // ingress_prog_map[0] = dump;
    // ingress_prog_map[1] = nat;

    // egress_prog_map[0] = dump;
    // egress_prog_map[1] = nat;

    uint32_t key;

    key = 1;
    if (adapter_.map_update_element(
            ingress_prog_array_fd_, &key, &ingress_nat_fd_, BPF_ANY)) {
        err("err 1");
        return ERROR;
    }
    if (adapter_.map_update_element(
            egress_prog_array_fd_, &key, &egress_nat_fd_, BPF_ANY)) {
        err("err 2");
        return ERROR;
    }

    key = 0;
    if (adapter_.map_update_element(
            ingress_prog_array_fd_, &key, &ingress_dump_fd_, BPF_ANY)) {
        err("err 3");
        return ERROR;
    }

    if (adapter_.map_update_element(
            egress_prog_array_fd_, &key, &egress_dump_fd_, BPF_ANY)) {
        err("err 4");
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::_disable_dump_mode() {

    // ingress_prog_map[0] = nat;
    // egress_prog_map[0] = nat;

    uint32_t key;

    key = 1;
    if (adapter_.map_delete_element(ingress_prog_array_fd_, &key)) {
        err("err 1");
        return ERROR;
    }
    if (adapter_.map_delete_element(egress_prog_array_fd_, &key)) {
        err("err 2");
        return ERROR;
    }

    key = 0;
    if (adapter_.map_update_element(
            ingress_prog_array_fd_, &key, &ingress_nat_fd_, BPF_ANY)) {
        err("err 3");
        return ERROR;
    }

    if (adapter_.map_update_element(
            egress_prog_array_fd_, &key, &egress_nat_fd_, BPF_ANY)) {
        err("err 4");
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::setup_grpc() {

    listen_address_ = config_.listen_address;

    builder_.AddListeningPort(listen_address_, InsecureServerCredentials());
    builder_.RegisterService(this);

    return SUCCESS;
}

void *
xnat::run_grpc_server(void *args) {

    std::unique_ptr<Server> server(builder_.BuildAndStart());

    info("Server listening on %s", listen_address_.c_str());

    server->Wait();

    pthread_exit(nullptr);
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

    ingress_prog_array_fd_ = adapter_.get_map_fd_by_name("ingress_prog_array");
    ingress_dump_fd_       = adapter_.get_prog_fd_by_name("xnat/dump/ingress");
    ingress_nat_fd_        = adapter_.get_prog_fd_by_name("xnat/nat/ingress");

    egress_prog_array_fd_ = adapter_.get_map_fd_by_name("egress_prog_array");
    egress_dump_fd_       = adapter_.get_prog_fd_by_name("xnat/dump/egress");
    egress_nat_fd_        = adapter_.get_prog_fd_by_name("xnat/nat/egress");

    return SUCCESS;
}

int
xnat::attach_bpf_progs() {

    ingress_ifindex_ = adapter_.attach_bpf_prog(
        config_.ingress_progsec, config_.ingress_ifname, config_.xdp_flags);
    if (static_cast<int32_t>(ingress_ifindex_) < 0) {
        throw std::string("failed attach_bpf_prog to ingress " +
                          config_.ingress_ifname);
    }
    info("Attach to interface %s:id(%d)",
         config_.ingress_ifname.c_str(),
         ingress_ifindex_);

    egress_ifindex_ = adapter_.attach_bpf_prog(
        config_.egress_progsec, config_.egress_ifname, config_.xdp_flags);
    if (static_cast<int32_t>(egress_ifindex_) < 0) {
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
        throw std::string("failed detach_bpf_prpg to ingress (" + std::to_string(ingress_ifindex_) + ")");
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
    map_name  = "ingress_prog_array";
    prog_name = "xnat/nat/ingress";

    err = _update_prog_array(map_name, prog_name, index);
    if (err) {
        throw std::string("failed update " + map_name);
    }

    info(
        "Update ingress prog array map index(%d):%s", index, prog_name.c_str());

    map_name  = "egress_prog_array";
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
    struct nat_record nt    = {};
    struct nm_k nt_key      = {};
    struct nm_k nt_prev_key = {};

    int port_pool_map_fd = adapter_.get_map_fd_by_name("port_pool");
    int nat_map_fd       = adapter_.get_map_fd_by_name("nat_table");

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

    pthread_t pt;
    err = pthread_create(&pt, nullptr, xnat::run_grpc_server, this);

    if (err != 0) {
        err("failed to create thread");
        return ERROR;
    }

    while (1) {
        err = epoll_wait(ep_fd, ev, EV_MAX, 5000);
        if (err < 0) {
            err("epoll ERROR");
            ;
        } else if (err == 0) {
            // _print_nat_table();
            ;
        } else {
            // check event
            for (int i = 0; i < err; i++) {
                if (ev[i].data.fd == sig_fd) {
                    struct signalfd_siginfo s_buf;
                    err = read(sig_fd, &s_buf, sizeof(s_buf));

                    info("");
                    info("Received signal");

                    pthread_kill(pt, SIGINT);

                    info("gRPC server stopped");

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

    int err;

    info("Event loop");

    err = _event_poll();
    if (err < 0) {
        throw std::string("Event ERROR");
    }

    info("Event loop finished");

    return SUCCESS;
}

int
xnat::init_maps() {
    info("Initialize maps");
    info(" - Initialize ifinfo_map");
    if (_init_ifinfo_map() < 0)
        throw std::string("failed initialize ifinfo_map");

    info(" - Initialize tx_map");
    if (_init_tx_map() < 0) throw std::string("failed initialize tx_map");

    info(" - Initialize port_pool");
    if (_init_port_pool() < 0) throw std::string("failed initialize port_pool");

    info(" - Initialize free_list");
    if (_init_freelist() < 0) throw std::string("failed initialize free_list");

    // info(" - Initialize vip_table");
    // if (_init_vip_table() < 0) throw std::string("failed initialize vip_table");

    // info(" - Initialize lpm_trie");
    // if (_init_lpm_trie() < 0) throw std::string("failed initialize lpm_trie");

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
        err("failed read hw addr");
        close(sock);
        return ERROR;
    }

    memcpy(info.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    err = ioctl(sock, SIOCGIFADDR, &ifr);
    if (err == 0) {
        memcpy(&saddr, &ifr.ifr_addr, sizeof(saddr));
        memcpy(&info.ip, &saddr.sin_addr, 4);

    } else {
        err("failed read ip addr");
        close(sock);
    }
    info(
        "   - ifindex(%d) addr(0x%08x/%u.%u.%u.%u) "
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

    close(sock);

    return SUCCESS;
}

int
xnat::_init_ifinfo_map() {
    int err;
    int map_fd;

    map_fd = adapter_.get_map_fd_by_name("ifinfo_map");

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
        throw std::string("Failed update tx_map");
    }

    err = adapter_.map_update_element(
        map_fd, &egress_ifindex_, &ingress_ifindex_, BPF_ANY);
    if (err < 0) {
        throw std::string("Failed update tx_map");
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

    int fd       = adapter_.get_map_fd_by_name("port_pool");
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
xnat::_init_vip_table() {
    int err;
    int fd;
    __be32 ip;
    __u32 vid;

    fd = adapter_.get_map_fd_by_name("ifinfo_map");

    struct ifinfo ingress_info, egress_info;

    if (adapter_.map_lookup_element(fd, &ingress_ifindex_, &ingress_info)) {
        err("failed lookup ingress ifinfo");
        return ERROR;
    }
    if (adapter_.map_lookup_element(fd, &egress_ifindex_, &egress_info)) {
        err("failed lookup egress ifinfo");
        return ERROR;
    }

    fd  = adapter_.get_map_fd_by_name("ingress_vip_table");
    ip  = htonl(ingress_info.ip);
    vid = 0;
    err = adapter_.map_update_element(fd, &vid, &ip, BPF_ANY);
    if (err) {
        err("failed update vip_table");
        return ERROR;
    }

    fd = adapter_.get_map_fd_by_name("egress_vip_table");
    ip = htonl(egress_info.ip);

    err = adapter_.map_update_element(fd, &vid, &ip, BPF_ANY);
    if (err) {
        err("failed update vip_table");
        return ERROR;
    }

    return SUCCESS;
}

int
xnat::_init_freelist() {
    int err;

    int fd = adapter_.get_map_fd_by_name("free_list");

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

int
xnat::_init_lpm_trie() {

    int err;
    int fd = adapter_.get_map_fd_by_name("lpm_trie");

    // TEST
    struct lpm_trie_key route_vid_0 = {
        .data      = {192, 168, 0, 0},
        .prefixlen = 24,
    };
    struct lpm_trie_key route_vid_100 = {
        .data      = {10, 10, 0, 0},
        .prefixlen = 24,
    };

    struct lpm_trie_key route_vid_200 = {
        .data      = {10, 20, 0, 0},
        .prefixlen = 24,
    };
    struct lpm_trie_key route_default = {
        .data      = {0, 0, 0, 0},
        .prefixlen = 0,
    };
    // struct lpm_trie_key route_vid_100 = {
    //     .data      = {10, 10, 0, 0},
    //     .prefixlen = 24,
    // };

    struct lpm_trie_value value;

    value.ifindex = ingress_ifindex_;
    value.vid     = 0;

    err = adapter_.map_update_element(fd, &route_vid_0, &value, BPF_ANY);
    if (err) {
        err("update vid 0");
        return ERROR;
    }

    value.vid = 100;
    err = adapter_.map_update_element(fd, &route_vid_100, &value, BPF_ANY);
    if (err) {
        err("update vid 100");
        return ERROR;
    }

    value.vid = 200;
    err = adapter_.map_update_element(fd, &route_vid_200, &value, BPF_ANY);
    if (err) {
        err("update vid 200");
        return ERROR;
    }

    struct lpm_trie_key route_vid_300 = {
        .data      = {10, 30, 0, 0},
        .prefixlen = 24,
    };
    struct lpm_trie_key route_vid_400 = {
        .data      = {10, 40, 0, 0},
        .prefixlen = 24,
    };

    value.ifindex = egress_ifindex_;
    value.vid     = 0;

    value.vid = 300;
    err = adapter_.map_update_element(fd, &route_vid_300, &value, BPF_ANY);
    if (err) {
        err("update vid 300");
        return ERROR;
    }

    value.vid = 400;
    err = adapter_.map_update_element(fd, &route_vid_400, &value, BPF_ANY);
    if (err) {
        err("update vid 400");
        return ERROR;
    }

    value.vid = 0;
    err = adapter_.map_update_element(fd, &route_default, &value, BPF_ANY);
    if (err) {
        err("update default");
        return ERROR;
    }

    return SUCCESS;
}

int
_sys_perf_event_open(struct perf_event_attr *attr,
                     pid_t pid,
                     int cpu,
                     int group_fd,
                     uint32_t flags) {

    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

}; // namespace xnat
