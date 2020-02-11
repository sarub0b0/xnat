#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include <unistd.h>

#include "message.h"

#include "controller.h"

void
usage(void) {
    printf(
        "Usage: ./controller [command] { --server-address|-S } [ "
        "address:port ] (root permission)\n");
    printf("\n");
    printf("  Commands:\n");
    printf("    vlan {add|del} dev IFNAME vid VLAN_ID vip IPADDR\n");
    printf("    nat {add|del} connect ingress IFNAME egress IFNAME\n");
    printf("    help\n");
}

struct command {
    std::string cmd;
    int (*func)(const std::vector<std::string> &argv, class controller &ctrl);
};

void
usage_route() {
    printf("  Commands:\n");
    printf("    route add {ingress|egress} vid VLAN_ID route x.x.x.x/x\n");
}

void
usage_vlan() {
    printf("  Commands:\n");
    printf("    vlan add dev IFNAME vid VLAN_ID vip IPADDR\n");
    printf("    vlan del dev IFNAME [ vip IPADDR ]\n");
}

void
usage_nat() {
    printf("  Commands:\n");
    printf("    nat {add|del} connect ingress IFNAME egress IFNAME\n");
}

int
do_vlan(const std::vector<std::string> &argv, class controller &ctrl) {
    if (argv.size() == 1) {
        usage_vlan();
        return ERROR;
    }

    printf("vlan\n");

    std::string mode = argv[1];

    std::string ifname = "";
    std::string vip    = "";
    std::string type   = "";
    uint32_t vid       = 0;
    for (auto itr = argv.begin(); itr != argv.end(); itr++) {
        if (*itr == "dev") {
            ifname = *(++itr);
        }
        if (*itr == "vid") {
            vid = std::stoi(*(++itr));
        }
        if (*itr == "vip") {
            vip = *(++itr);
        }
        if (*itr == "ingress") {
            type = "ingress";
        }
        if (*itr == "egress") {
            type = "egress";
        }
    }

    if (!type.size() || !ifname.size()) goto err;

    if (mode == "add") {
        if (!vip.size()) goto err;

        if (ctrl.add_vip(type, ifname, vid, vip) < 0) {
            return ERROR;
        }
    } else if (mode == "del") {
        ctrl.del_vlan_iface(type, ifname, vid);
    } else {
        goto err;
    }

    return SUCCESS;
err:
    usage_vlan();
    return ERROR;
}

int
do_nat(const std::vector<std::string> &argv, class controller &ctrl) {
    if (argv.size() == 1) {
        usage_nat();
        return ERROR;
    }

    printf("nat\n");
    return SUCCESS;
}

struct command cmds[] = {
    {"vlan", do_vlan},
    {"nat", do_nat},
};

struct command *
command_perser(std::vector<std::string> &argv, struct config &cfg) {
    if (argv.size() == 1) {
        return nullptr;
    }

    std::string argv0;

    for (auto itr = argv.begin(); itr != argv.end(); itr++) {
        if (*itr == "--server-address" || *itr == "-S") {
            argv.erase(itr);
            if (itr != argv.end()) {
                cfg.server_address = *itr;
                argv.erase(itr);
                break;
            } else {
                return nullptr;
            }
        }
    }

    argv0 = argv[0];

    for (struct command *c = cmds; c->cmd.c_str(); c++) {
        if (argv0 == c->cmd) {
            return c;
        }
    }

    return nullptr;
}

int
main(int argc, char const *argv[]) {

    if (getuid() != 0) {
        err("Permission denied. Please exec root user");
        return 1;
    }

    if (argc == 1) {
        usage();
        return 1;
    }

    struct config cfg = {};

    std::vector<std::string> argv_vec;

    for (int i = 1; i < argc; i++) {
        argv_vec.push_back(std::string(argv[i]));
    }

    for (auto &&a : argv_vec) {
        if (a == "help") {
            usage();
            return 0;
        }
    }

    cfg.server_address = "localhost:10000";

    struct command *cmd;

    try {
        cmd = command_perser(argv_vec, cfg);
        if (!cmd) {
            usage();
            throw std::string("command parse faild");
        }

        info("Configure Server address %s", cfg.server_address.c_str());

        class controller ctrl(cfg);
        ctrl.setup_grpc();

        cmd->func(argv_vec, ctrl);

    } catch (const std::string &e) {
        err("%s", e.c_str());
    }
    return 0;
}
