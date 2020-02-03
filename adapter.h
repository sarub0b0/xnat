#pragma once

#include <errno.h>

#include "loader.h"

class adapter {
   public:
    adapter(){};
    ~adapter(){};
    // int load_bpf_prog(std::string &obj_name, struct config &cfg);
    int load_bpf_prog(const std::string &obj_name,
                      const struct bpf_prog_load_attr &attr);
    int attach_bpf_prog(const std::string &progsec,
                        const std::string &ifname,
                        uint32_t xdp_flags);

    int attach_bpf_prog(int prog_fd,
                        const std::string &ifname,
                        uint32_t xdp_flags);
    int attach_bpf_prog(int prog_fd, uint32_t ifindex, uint32_t xdp_flags);

    int detach_bpf_prpg(int prog_fd, uint32_t ifindex, uint32_t xdp_flags);

    int pin_maps(const std::string &map_pin_dir);
    int unpin_maps(const std::string &load_obj_name,
                   const std::string &map_pin_dir);

    int get_map_fd_by_name(const std::string &name);
    int get_prog_fd_by_name(const std::string &name);

    int map_update_element(int fd, void *key, void *value, uint32_t flags);
    int map_lookup_element(int fd, void *key, void *value);
    int map_delete_element(int fd, void *key);
    int map_get_next_key(int fd, void *key, void *next_key);

    int open_bpf_map_file(const std::string &dir, const std::string &filename);

   private:
    class loader loader_;
};

int
// adapter::load_bpf_prog(std::string &obj_name, struct config &cfg) {
adapter::load_bpf_prog(const std::string &obj_name,
                       const struct bpf_prog_load_attr &attr) {

    return loader_.bpf_prog_load(obj_name, attr);
}

int
adapter::attach_bpf_prog(const std::string &progsec,
                         const std::string &ifname,
                         uint32_t xdp_flags) {

    uint32_t ifindex;
    int prog_fd;

    ifindex = if_nametoindex(ifname.c_str());
    if (!ifindex) {
        err("unknown ingress interface %s", ifname.c_str());
        return ERROR;
    }

    prog_fd = get_prog_fd_by_name(progsec);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
        err("Can't attach to interface %s:%d", ifname.c_str(), ifindex);
        return ERROR;
    }

    return ifindex;
}

int
adapter::attach_bpf_prog(int prog_fd,
                         const std::string &ifname,
                         uint32_t xdp_flags) {
    uint32_t ifindex;
    ifindex = if_nametoindex(ifname.c_str());
    if (!ifindex) {
        err("unknown ingress interface %s", ifname.c_str());
        return ERROR;
    }
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
        err("Can't attach to interface %s:%d", ifname.c_str(), ifindex);
        return 0;
    }

    return ifindex;
}

int
adapter::attach_bpf_prog(int prog_fd, uint32_t ifindex, uint32_t xdp_flags) {
    return bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
}

int
adapter::detach_bpf_prpg(int prog_fd, uint32_t ifindex, uint32_t xdp_flags) {
    return bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
}

int
adapter::pin_maps(const std::string &map_pin_dir) {
    int err;

    const std::unordered_map<std::string, struct bpf_map *> &maps =
        loader_.get_maps();

    for (auto &&hash : maps) {
        std::string name    = hash.first;
        struct bpf_map *map = hash.second;
        std::string dir     = map_pin_dir + "/" + name;

        if (access(dir.c_str(), F_OK) != -1) {
            info(" - Unpinning (remove) prev map in %s", name.c_str());
            err = bpf_map__unpin(map, dir.c_str());
            if (err) {
                err("Failed unpinning map in %s", name.c_str());
                continue;
            }
        }
        err = bpf_map__pin(map, dir.c_str());
        if (err) {
            err("Failed pinning map in %s", dir.c_str());
            continue;
        }
        info(" - Pinning map in %s", name.c_str());
    }

    return SUCCESS;
}

int
adapter::unpin_maps(const std::string &load_obj_name,
                    const std::string &map_pin_dir) {
    int err;
    struct bpf_object *obj;

    obj = loader_.get_object_by_name(load_obj_name);
    err = bpf_object__unpin_maps(obj, map_pin_dir.c_str());
    if (err) {
        err("Failed unpinning maps in %s", map_pin_dir.c_str());
        return ERROR;
    }
    return SUCCESS;
}

int
adapter::get_prog_fd_by_name(const std::string &name) {
    return loader_.get_prog_fd_by_name(name);
}

int
adapter::get_map_fd_by_name(const std::string &name) {
    return loader_.get_map_fd_by_name(name);
}

int
adapter::map_update_element(int fd, void *key, void *value, uint32_t flags) {
    auto err = bpf_map_update_elem(fd, key, value, flags);
    if (err) {
        err("bpf_map_update_elem failed. %s", strerror(errno));
    }
    return err;
}

int
adapter::map_lookup_element(int fd, void *key, void *value) {
    auto err = bpf_map_lookup_elem(fd, key, value);
    if (err) {
        err("bpf_map_lookup_elem failed. %s", strerror(errno));
    }
    return err;
}

int
adapter::map_delete_element(int fd, void *key) {
    auto err = bpf_map_delete_elem(fd, key);
    if (err) {
        err("bpf_map_delete_elem failed. %s", strerror(errno));
    }
    return err;
}

int
adapter::map_get_next_key(int fd, void *key, void *next_key) {
    auto err = bpf_map_get_next_key(fd, key, next_key);
    if (err) {
        err("bpf_map_get_next_key failed. %s", strerror(errno));
    }
    return err;
}

int
adapter::open_bpf_map_file(const std::string &dir, const std::string &filename) {
    return loader_.open_bpf_map_file(dir, filename);
}
