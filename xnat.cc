#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

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
#include <net/if.h>

#include "stats.h"
#include "message.h"
#include "utils.h"
#include "nat.h"
#include "ifinfo.h"
#include "prog.h"
#include "getopt_long.h"
class loader {
   public:
    loader();
    ~loader();

    struct config cfg;
    struct bpf_object *obj;

   private:
};
class dump {
   public:
   private:
};
class stats {
   public:
   private:
};
class xnat {
   public:
   private:
};

int
main(int argc, char const *argv[]) {

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        err("rlimit error");
        return 1;
    }

    int c;
    while ((c = gopt.getopt_long(
                    argc, argv, short_options, long_options, nullptr) != -1)) {

        switch (c) {
            case '':
                break;
            default:
                break;
        }
    }

    return 0;
}
