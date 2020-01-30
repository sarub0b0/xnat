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
#include "getopt_long.h"
// #include "utils.h"

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

void
usage(void) {
    printf("Usage: ./xnat_pcap [options] (root permission)\n");
    printf("\n");
    printf("  Options:\n");
    printf("    --filename, -f: pcap file name\n");
    printf("    --quiet, -q: disable hex dump stdout\n");
    printf("    --help,    -h: help\n");
    printf("\n");
}
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

static inline uint32_t
bpf_num_possible_cpus(void) {
    uint32_t cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        err("Failed to get # of possible cpus: '%s'!", hstrerror(-cpus));
        exit(1);
    }
    return cpus;
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
do_attach(int idx, int fd, const char *name, uint32_t xdp_flags) {
    int err = 0;

    return err;
}

int
do_detach(int idx, const char *name) {
    int err = 0;

    return err;
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

const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"filename", required_argument, NULL, 'f'},
    {"quiet", no_argument, NULL, 'q'},
};

const char short_options[] = "f:qh";

int
main(int argc, char *const argv[]) {

    struct bpf_map_info info = {0};
    std::string filename;
    std::string pin_dir;
    int map_fd;
    int numcpus = bpf_num_possible_cpus();

    filename = default_filename;

    enum bpf_perf_event_ret ret;

    pin_dir = pin_basedir + "/" + subdir;

    int c;
    while ((c = gopt.getopt_long(
                argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'f':
                filename = optarg;
                break;
            case 'q':
                verbose = 0;
                break;
            case 'h':
                usage();
                exit(1);
            default:
                usage();
                exit(1);
        }
    }

    map_fd = open_bpf_map_file(pin_dir, map_name, &info);

    if (map_fd < 0) {
        err("Cannot open %s", pin_dir.c_str());
        return 1;
    }

    if (signal(SIGINT, sig_handler) || signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        err("signal");
        return 1;
    }

    test_bpf_perf_event(map_fd, numcpus);

    for (int i = 0; i < numcpus; i++)
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) return 1;

    pd = nullptr;

    pd = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pd) {
        err("pcap_open_dead failed");
        goto out;
    }

    pdumper = nullptr;

    pdumper = pcap_dump_open(pd, filename.c_str());
    if (!pdumper) {
        err("pcap_dump_open failed");
        goto out;
    }

    ret = perf_event_poller_multi(
        pmu_fds, headers, numcpus, print_bpf_output, &done);

    pcap_dump_close(pdumper);
    pcap_close(pd);

out:
    info("");
    info("%u packet samples stored in %s", pcap_pkts, filename.c_str());
    return ret;
}
