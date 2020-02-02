#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <errno.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <libgen.h>
#include <signal.h>
#include <poll.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>

#include "message.h"
#include "adapter.h"
#include "config.h"
#include "utils.h"

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#define MAX_CPUS 128

const std::string pin_basedir      = "/sys/fs/bpf";
const std::string map_name         = "pcap_map";
const std::string default_filename = "xnat.pcap";
const std::string subdir           = "xnat";

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];
static uint32_t prog_id;

static pcap_t *pd;
static pcap_dumper_t *pdumper;
static uint32_t pcap_pkts;

int verbose = 1;

static int
sys_perf_event_open(struct perf_event_attr *attr,
                    pid_t pid,
                    int cpu,
                    int group_fd,
                    unsigned long flags) {
    int fd;

    fd = syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
    return fd;
}

static int
open_bpf_prog_file(std::string filename,
                   std::string progsec,
                   struct bpf_object **obj,
                   struct bpf_program **prog,
                   int *prog_fd,
                   int *progsec_fd) {

    int err;

    err = bpf_prog_load(filename.c_str(), BPF_PROG_TYPE_XDP, obj, prog_fd);
    if (*prog_fd < 0) {
        err("failed to open bpf map file: %s err(%d):%s",
            filename.c_str(),
            errno,
            hstrerror(errno));
        return -1;
    }

    *prog = bpf_object__find_program_by_title(*obj, progsec.c_str());
    if (!prog) {
        err("Couldn't find a program in ELF section '%s'", progsec.c_str());
        return -1;
    }

    *progsec_fd = bpf_program__fd(*prog);
    if (*progsec_fd < 0) {
        err("bpf_program__fd failed");
        return -1;
    }

    return 0;
}

static int
open_bpf_map_file(std::string pin_dir,
                  std::string map_name,
                  struct bpf_map_info *info) {

    int fd  = -1;
    int err = -1;

    std::string filename;
    uint32_t info_len = sizeof(*info);

    filename = pin_dir + "/" + map_name;

    fd = bpf_obj_get(filename.c_str());
    if (fd < 0) {
        err("failed to open bpf map file: %s err(%d):%s",
            filename.c_str(),
            errno,
            hstrerror(errno));
        return fd;
    }
    if (info) {
        err = bpf_obj_get_info_by_fd(fd, info, &info_len);
        if (err) {
            err("%s() can't get info - %s", __func__, hstrerror(errno));
            return -1;
        }
    }

    return fd;
}
int
attach(int prog_fd, int map_fd) {
    int err = 0;
    int key = 0;

    err = bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
    if (err) {
        return -1;
    }

    return 0;
}

int
detach(int prog_fd, int map_fd) {
    int err = 0;
    int key = 0;

    err = bpf_map_delete_elem(map_fd, &key);
    if (err) {
        return -1;
    }

    return 0;
}

#define SAMPLE_SIZE 1024
#define NANOSEC_PER_SEC 1000

struct sample {
    uint16_t cookie;
    uint16_t pkt_len;
    uint8_t pkt_data[SAMPLE_SIZE];
} __attribute__((packed));

static enum bpf_perf_event_ret
print_bpf_output(void *data, int size) {
    struct sample *e = (struct sample *) data;

    struct pcap_pkthdr h = {
        .caplen = SAMPLE_SIZE,
        .len    = e->pkt_len,
    };

    struct timespec ts;

    int err = 0;

    if (e->cookie != 0xdead) {
        err("BUG cookie 0x%x sized %d", e->cookie, size);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    err = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (err < 0) {
        err("Error with gettimeofday! (%i)", err);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    h.ts.tv_sec  = ts.tv_sec;
    h.ts.tv_usec = ts.tv_nsec / NANOSEC_PER_SEC;

    if (verbose) {
        printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
        int is_odd = e->pkt_len % 2;
        int len    = is_odd ? e->pkt_len - 1 : e->pkt_len;

        for (int i = 0; i < len; i += 2) {
            if (i % 16 == 0) {
                printf("\n\t 0x%04x: ", i);
            }
            printf("%02x%02x", e->pkt_data[i], e->pkt_data[i]);
            printf(" ");
        }
        if (is_odd) {
            printf("%02x", e->pkt_data[len]);
        }
        printf("\n");
    }

    pcap_dump((unsigned char *) pdumper, &h, e->pkt_data);
    pcap_pkts++;
    return LIBBPF_PERF_EVENT_CONT;
}

static void
test_bpf_perf_event(int map_fd, int num) {
    struct perf_event_attr attr = {
        .sample_type   = PERF_SAMPLE_RAW,
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    for (int i = 0; i < num; i++) {
        int key    = i;
        pmu_fds[i] = sys_perf_event_open(&attr, -1, i, -1, 0);

        assert(pmu_fds[i] >= 0);
        assert(bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY) == 0);
        ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }
}

static int done;

static void
sig_handler(int signo) {
    done = 1;
}

struct perf_event_sample {
    struct perf_event_header header;
    uint32_t size;
    char data[];
};

struct lost {
    struct perf_event_header header;
    uint64_t id;
    uint64_t lost;
};

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data) {
    struct perf_event_sample *e = (struct perf_event_sample *) hdr;
    perf_event_print_fn fn      = (perf_event_print_fn) private_data;
    enum bpf_perf_event_ret ret;

    if (e->header.type == PERF_RECORD_SAMPLE) {
        ret = fn(e->data, e->size);
        if (ret != LIBBPF_PERF_EVENT_CONT) {
            return ret;
        }
    } else if (e->header.type == PERF_RECORD_LOST) {
        struct lost *lost = (struct lost *) e;

        info("lost %lu events", lost->lost);
    } else {
        info("unknown event type=%d size=%d", e->header.type, e->header.size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

int page_size;
int page_cnt = 8;

int
perf_event_mmap_header(int fd, struct perf_event_mmap_page **header) {
    void *base;
    int mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        err("mmap err");
        return -1;
    }

    *header = (struct perf_event_mmap_page *) base;
    return 0;
}

enum bpf_perf_event_ret
perf_event_poller_multi(int *fds,
                        struct perf_event_mmap_page **headers,
                        int num_fds,
                        perf_event_print_fn output_fn,
                        int *done) {
    enum bpf_perf_event_ret ret;

    struct pollfd *pfds;
    void *buf  = NULL;
    size_t len = 0;

    pfds = new struct pollfd[num_fds];
    if (!pfds) {
        return LIBBPF_PERF_EVENT_ERROR;
    }

    for (int i = 0; i < num_fds; i++) {
        pfds[i].fd     = fds[i];
        pfds[i].events = POLLIN;
    }

    while (!*done) {
        poll(pfds, num_fds, 1000);
        for (int i = 0; i < num_fds; i++) {
            if (!pfds[i].revents) {
                continue;
            }

            ret = bpf_perf_event_read_simple(headers[i],
                                             page_cnt * page_size,
                                             page_size,
                                             &buf,
                                             &len,
                                             bpf_perf_event_print,
                                             (void *) output_fn);
            if (ret != LIBBPF_PERF_EVENT_CONT) {
                break;
            }
        }
    }

    free(buf);
    delete pfds;

    return ret;
}
int
pin_maps_in_bpf_object(struct bpf_object *obj, const char *pin_dir) {
    char map_filename[PATH_MAX];
    int err, len;
    struct bpf_map *map;

    info("map pinned dir (%s)", pin_dir);

    info("map-name [%s]", map_name.c_str());

    map = bpf_object__find_map_by_name(obj, map_name.c_str());
    if (!map) {
        fprintf(stderr,
                "ERR: bpf_object__find_map_by_name failed. [%s]\n",
                map_name.c_str());
        return EXIT_FAIL_BPF;
    }

    len = snprintf(map_filename, PATH_MAX, "%s/%s", pin_dir, map_name.c_str());
    if (len < 0) {
        err("creating map name");
        return EXIT_FAIL_OPTION;
    }

    if (access(map_filename, F_OK) != -1) {
        info(" - Unpinning (remove) prev map in %s", map_filename);
        err = bpf_map__unpin(map, map_filename);
        if (err) {
            err("Unpinning map in %s", map_filename);
            return EXIT_FAIL_OPTION;
        }
    }
    info(" - Pinning map in %s", map_filename);

    err = bpf_map__pin(map, map_filename);
    if (err) {
        return EXIT_FAIL_BPF;
    }
    return 0;
}
class dump {
   public:
    dump(const struct config &config) : config_(config){};
    ~dump();

   private:
    class adapter adapter_;
    struct config config_;
    int verbose_ = 0;
};

