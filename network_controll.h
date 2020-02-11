#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <unordered_map>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>

#include "define.h"
#include "message.h"

namespace xnat {

struct addr_info {
    uint32_t addr;
    uint32_t prefixlen;
};

class network_controll {
   public:
    network_controll(const std::string &ingress, const std::string &egress) {
        _init();

        uint32_t ifindex;
        ifaces_[ingress] = _name2ifindex(ingress);
        ifaces_[egress]  = _name2ifindex(egress);
    }
    ~network_controll() {
        nl_close(sock_);
    }

    int add_vip(const std::string &ifname,
                uint32_t vid,
                const std::string &addr);
    int del_vip();
    int del_vlan_iface(const std::string &ifname);

   private:
    int _init();

    int _add_vlan(const std::string &ifname,
                  const std::string &vlan_ifname,
                  uint32_t vid);
    int _del_vlan(const std::string &ifname);

    int _add_vip(const std::string &ifname, const std::string &addr);
    int _del_vip();
    int _link_up();
    int _link_down();
    int _check_link_state(struct rtnl_link *link, uint32_t flags);

    int _str2ipv4_info(const std::string &str, struct addr_info *info);

    uint32_t _name2ifindex(const std::string &name);

    struct nl_sock *sock_;

    std::unordered_map<std::string, uint32_t> ifaces_;
    std::unordered_map<std::string, uint32_t> vlan_ifaces_;
    std::unordered_map<std::string, struct addr_info> vip_;

    // struct rtnl_link *link_;
    // struct nl_cache *link_cache_;

    // struct rtnl_addr *addr_;
    // struct nl_cache *addr_cache_;
};

int
network_controll::_init() {
    int err;

    sock_ = nl_socket_alloc();
    if (!sock_) {
        err("failed nl_socket_alloc");
        return ERROR;
    }

    err = nl_connect(sock_, NETLINK_ROUTE);

    if (err < 0) {
        err("Unable to connect sock");
        return ERROR;
    }

    // err = rtnl_link_alloc_cache(sock_, AF_UNSPEC, &link_cache_);
    // if (err < 0) {
    //     err("Unable to allocate link cache");
    //     return ERROR;
    // }

    // link_ = rtnl_link_alloc();

    // err = rtnl_addr_alloc_cache(sock_, &addr_cache_);
    // if (err < 0) {
    //     err("Unable to allocate addr cache");
    //     return ERROR;
    // }

    // addr_ = rtnl_addr_alloc();

    info("Init network controll");

    return SUCCESS;
}

int
network_controll::add_vip(const std::string &ifname,
                          uint32_t vid,
                          const std::string &addr) {
    std::string vlan_ifname;
    vlan_ifname = ifname + "." + std::to_string(vid);

    info("Add vlan interface %s:%s", vlan_ifname.c_str(), addr.c_str());

    if (_add_vlan(ifname, vlan_ifname, vid) < 0) return ERROR;

    if (_add_vip(vlan_ifname, addr) < 0) return ERROR;

    return SUCCESS;
}

int
network_controll::del_vip() {
    return SUCCESS;
}

int
network_controll::del_vlan_iface(const std::string &ifname) {
    info("Delete vlan iface %s", ifname.c_str());
    if (_del_vlan(ifname) < 0) return ERROR;

    return SUCCESS;
}

int
network_controll::_add_vlan(const std::string &ifname,
                            const std::string &vlan_ifname,
                            uint32_t vid) {

    int err;

    struct rtnl_link *link;
    struct nl_cache *cache;
    uint32_t ifindex;

    err = rtnl_link_alloc_cache(sock_, AF_UNSPEC, &cache);
    if (err < 0) {
        err("Unable to allocate link cache");
        return ERROR;
    }

    ifindex = rtnl_link_name2i(cache, ifname.c_str());
    if (!ifindex) {
        err("Can't lookup %s", ifname.c_str());
        return ERROR;
    }

    link = rtnl_link_vlan_alloc();

    rtnl_link_set_link(link, ifindex);
    rtnl_link_set_name(link, vlan_ifname.c_str());

    rtnl_link_vlan_set_id(link, vid);

    rtnl_link_set_flags(link, IFF_RUNNING | IFF_UP);
    // rtnl_link_set_flags(link, 0);

    err = rtnl_link_add(sock_, link, NLM_F_CREATE);
    if (err < 0) {
        err("Can't create iface %s", vlan_ifname.c_str());
        return ERROR;
    }

    rtnl_link_put(link);

    ifindex = _name2ifindex(vlan_ifname);

    if (ifindex < 1) {
        err("Can't lookup %s", vlan_ifname.c_str());
        return ERROR;
    }

    vlan_ifaces_[vlan_ifname] = ifindex;

    return SUCCESS;
}

int
network_controll::_del_vlan(const std::string &ifname) {
    int err;
    struct rtnl_link *link;
    uint32_t ifindex;

    link = rtnl_link_alloc();

    rtnl_link_set_name(link, ifname.c_str());

    if (rtnl_link_delete(sock_, link) < 0) {
        err("Can't delete iface %s", ifname.c_str());
        return ERROR;
    }

    rtnl_link_put(link);

    vlan_ifaces_.erase(ifname);

    return SUCCESS;
}

int
network_controll::_add_vip(const std::string &ifname, const std::string &addr) {
    int err;
    uint32_t ifindex;
    uint32_t prefixlen;
    struct rtnl_addr *rtnl_addr;

    struct nl_addr *nl_addr;
    struct addr_info info = {};

    _str2ipv4_info(addr, &info);

    rtnl_addr = rtnl_addr_alloc();
    if (!rtnl_addr) {
        err("Can't allocate rtnl_addr");
        return ERROR;
    }

    nl_addr = nl_addr_build(AF_INET, &info.addr, 4);
    if (!nl_addr) {
        err("Can't build addr");
        return ERROR;
    }

    info("Add addr %s(%d) 0x%x/%d",
         ifname.c_str(),
         vlan_ifaces_[ifname],
         info.addr,
         info.prefixlen);

    rtnl_addr_set_ifindex(rtnl_addr, vlan_ifaces_[ifname]);

    rtnl_addr_set_local(rtnl_addr, nl_addr);
    rtnl_addr_set_prefixlen(rtnl_addr, info.prefixlen);

    rtnl_addr_add(sock_, rtnl_addr, NLM_F_CREATE);

    rtnl_addr_put(rtnl_addr);

    vip_[ifname] = info;

    return SUCCESS;
}

int
network_controll::_del_vip() {
    return SUCCESS;
}

int
network_controll::_link_up() {
    return SUCCESS;
}

int
network_controll::_link_down() {
    return SUCCESS;
}

uint32_t
network_controll::_name2ifindex(const std::string &name) {

    int err;
    struct nl_cache *cache;
    uint32_t ifindex;
    int max_loop = 10;

    err = rtnl_link_alloc_cache(sock_, AF_UNSPEC, &cache);
    if (err < 0) {
        err("Unable to allocate link cache");
        return ERROR;
    }

    ifindex = 0;
    for (int i = 0; i < max_loop; i++) {
        ifindex = rtnl_link_name2i(cache, name.c_str());
        usleep(200000);
        if (!ifindex) {
            info("Wait lookup %s", name.c_str());
            continue;
        } else
            break;
    }

    if (!ifindex) {
        err("Can't lookup %s", name.c_str());
        return ERROR;
    }

    return ifindex;
}

int
network_controll::_str2ipv4_info(const std::string &str,
                                 struct addr_info *info) {

    uint32_t addr;
    int first = 0;
    int last  = str.find_first_of("/");

    std::string str_addr(str, first, last - first);

    first = last + 1;

    std::string str_prefixlen(str, first, str.size());

    info("address(%s) prefix(%s)", str_addr.c_str(), str_prefixlen.c_str());

    inet_pton(AF_INET, str_addr.c_str(), &addr);

    info->addr      = addr;
    info->prefixlen = std::stoi(str_prefixlen);

    return SUCCESS;
}

int
network_controll::_check_link_state(struct rtnl_link *link, uint32_t flags) {
    uint32_t current_flags = 0;

    int max_loop = 10;
    int cnt      = 0;

    info("check flag(0x%x)", flags);
    while (current_flags != flags) {
        current_flags = rtnl_link_get_flags(link);

        current_flags = current_flags & flags;

        info("flag(0x%x)", current_flags);

        if (current_flags == flags) {
            break;
        }
        if (max_loop == cnt) {
            err("timeout check link state");
            return ERROR;
        }
        usleep(500000);
        cnt++;
    }

    return SUCCESS;
}

} // namespace xnat
