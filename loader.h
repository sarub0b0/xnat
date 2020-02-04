#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#include "define.h"
#include "message.h"

class loader {
   public:
    loader();
    ~loader();

    int bpf_prog_load(const std::string &obj_name,
                      const struct bpf_prog_load_attr &attr);

    int get_map_fd_by_name(const std::string &name);
    int get_prog_fd_by_name(const std::string &name);

    struct bpf_object *get_object_by_name(const std::string &name);
    struct bpf_program *get_program_by_name(const std::string &name);
    struct bpf_map *get_map_by_name(const std::string &name);

    int open_bpf_map_file(const std::string &dir, const std::string &filename);

    const std::unordered_map<std::string, int> &get_map_fds();
    const std::unordered_map<std::string, struct bpf_map *> &get_maps();

   private:
    std::unordered_map<std::string, struct bpf_object *> objects_;
    std::unordered_map<std::string, struct bpf_program *> programs_;
    std::unordered_map<std::string, struct bpf_map *> maps_;
    std::unordered_map<std::string, struct bpf_prog_info *> prog_infos_;
    std::unordered_map<std::string, struct bpf_map_info *> map_infos_;

    std::unordered_map<std::string, int> map_fds_;
    std::unordered_map<std::string, int> prog_fds_;
};

loader::loader() {
}

loader::~loader() {
    for (auto &&obj : objects_) {
        bpf_object__close(obj.second);
    }

    for (auto &&fd : map_fds_) {
        close(fd.second);
    }

    for (auto &&fd : prog_fds_) {
        close(fd.second);
    }
}

int
loader::bpf_prog_load(const std::string &obj_name,
                      const struct bpf_prog_load_attr &attr) {
    struct bpf_object *obj;

    int fd;

    if (bpf_prog_load_xattr(&attr, &obj, &fd)) {
        err("bpf_prog_load_xattr faild");
        return ERROR;
    }

    objects_[obj_name]  = obj;
    prog_fds_[obj_name] = fd;

    std::string name;
    struct bpf_program *prog;
    struct bpf_map *map;

    bpf_object__for_each_program(prog, obj) {
        name = bpf_program__title(prog, false);

        if (!prog) {
            err("bpf_object__find_program_by_title failed. [%s]\n",
                name.c_str());
            return ERROR;
        }

        programs_[name] = prog;
        prog_fds_[name] = bpf_program__fd(prog);
        info(" - prog %s:fd(%d)", name.c_str(), prog_fds_[name]);
    }

    bpf_map__for_each(map, obj) {
        name = bpf_map__name(map);

        if (!map) {
            err("bpf_object__find_map_by_name failed. [%s]\n", name.c_str());
            return ERROR;
        }
        maps_[name]    = map;
        map_fds_[name] = bpf_map__fd(map);
        info(" - map %s:fd(%d)", name.c_str(), map_fds_[name]);
    }

    return SUCCESS;
}

struct bpf_object *
loader::get_object_by_name(const std::string &name) {
    auto obj = objects_.find(name);
    if (obj == objects_.end()) {
        return nullptr;
    } else {
        return obj->second;
    }
}

struct bpf_program *
loader::get_program_by_name(const std::string &name) {
    auto prog = programs_.find(name);
    if (prog == programs_.end()) {
        return nullptr;
    } else {
        return prog->second;
    }
}

struct bpf_map *
loader::get_map_by_name(const std::string &name) {
    auto map = maps_.find(name);
    if (map == maps_.end()) {
        return nullptr;
    } else {
        return map->second;
    }
}

int
loader::get_map_fd_by_name(const std::string &name) {
    auto map = map_fds_.find(name);
    if (map == map_fds_.end()) {
        return ERROR;
    } else {
        return map->second;
    }
}
int
loader::get_prog_fd_by_name(const std::string &name) {
    auto prog = prog_fds_.find(name);
    if (prog == prog_fds_.end()) {
        return ERROR;
    } else {
        return prog->second;
    }
}

const std::unordered_map<std::string, int> &
loader::get_map_fds() {
    return map_fds_;
}

const std::unordered_map<std::string, struct bpf_map *> &
loader::get_maps() {
    return maps_;
}

int
loader::open_bpf_map_file(const std::string &dir, const std::string &filename) {
    int fd;

    std::string path = dir + "/" + filename;

    fd = bpf_obj_get(path.c_str());

    if (fd < 0) {
        err("failed to open bpf map file: %s err(%d):%s",
            path.c_str(),
            errno,
            strerror(errno));
        return ERROR;
    }

    map_fds_[filename] = fd;

    return SUCCESS;
}

