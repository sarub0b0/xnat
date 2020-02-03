#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <stdexcept>

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
// #include "config.h"
#include "utils.h"
struct config {
    std::string map_pin_dir;
    std::string map_name;
    std::string dumpfile;
    std::string pin_basedir;
    std::string subdir;
    int verbose;
    int nr_cpus;
};

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#define MAX_CPUS 128

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

#define SAMPLE_SIZE 1024
#define NANOSEC_PER_SEC 1000

struct sample {
    uint16_t cookie;
    uint16_t pkt_len;
    uint8_t pkt_data[SAMPLE_SIZE];
} __attribute__((packed));

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

class dump {

   public:
    dump(){};
    ~dump();

    void set_config(struct config &cfg);
    int set_signal();
    int open_bpf_map_file(const std::string &dir, const std::string &filename);
    int attach();
    int detach();
    void test_bpf_perf_event();
    int perf_event_mmap();
    int open_pcap();
    void close_pcap();
    void print_result();

    enum bpf_perf_event_ret perf_event_poller_multi();

   private:
    int _sys_perf_event_open(struct perf_event_attr &attr,
                             pid_t pid,
                             int cpu,
                             int group_fd,
                             uint32_t flags);
    static enum bpf_perf_event_ret _print_bpf_output(void *data, int size);
    static enum bpf_perf_event_ret _bpf_perf_event_print(
        struct perf_event_header *hdr, void *private_data);

    int _perf_event_mmap_header(int fd, struct perf_event_mmap_page **header);
    static void _sig_handler(int signo);

    class adapter adapter_;
    struct config config_;
    static int verbose_;

    struct perf_event_attr perf_event_perf_attr_;
    struct perf_event_mmap_page **headers_;

    int pmu_fds_[MAX_CPUS];

    pcap_t *pd_ = nullptr;
    static pcap_dumper_t *pdumper_;

    static uint32_t pcap_pkts_;

    int page_size_;
    int page_cnt_ = 8;

    int nr_cpus_;

    int map_fd_;

    static int done_;
};

int dump::done_               = 0;
int dump::verbose_            = 0;
uint32_t dump::pcap_pkts_     = 0;
pcap_dumper_t *dump::pdumper_ = nullptr;

dump::~dump() {
}

void
dump::set_config(struct config &cfg) {
    config_ = cfg;
}

void
dump::_sig_handler(int signo) {
    done_ = 1;
}

int
dump::set_signal() {
    if (signal(SIGINT, _sig_handler) || signal(SIGHUP, _sig_handler) ||
        signal(SIGTERM, _sig_handler)) {
        err("signal");
        return ERROR;
    }

    done_ = 0;

    return SUCCESS;
}

int
dump::_sys_perf_event_open(struct perf_event_attr &attr,
                           pid_t pid,
                           int cpu,
                           int group_fd,
                           uint32_t flags) {

    return syscall(__NR_perf_event_open,
                   &perf_event_perf_attr_,
                   pid,
                   cpu,
                   group_fd,
                   flags);
}

int
dump::open_bpf_map_file(const std::string &dir, const std::string &filename) {

    int err;
    err = adapter_.open_bpf_map_file(dir, filename);
    if (err < 0) {
        throw std::string("Can't open " + dir + "/" + filename);
    }

    map_fd_ = adapter_.get_map_fd_by_name(config_.map_name);

    return SUCCESS;
}

enum bpf_perf_event_ret
dump::_print_bpf_output(void *data, int size) {
    struct sample *e = static_cast<struct sample *>(data);

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

    if (verbose_) {
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

    pcap_dump(reinterpret_cast<unsigned char *>(pdumper_), &h, e->pkt_data);
    pcap_pkts_++;
    return LIBBPF_PERF_EVENT_CONT;
}

enum bpf_perf_event_ret
dump::_bpf_perf_event_print(struct perf_event_header *hdr, void *private_data) {

    struct perf_event_sample *e =
        reinterpret_cast<struct perf_event_sample *>(hdr);
    perf_event_print_fn fn =
        reinterpret_cast<perf_event_print_fn>(private_data);
    enum bpf_perf_event_ret ret;

    if (e->header.type == PERF_RECORD_SAMPLE) {
        ret = fn(e->data, e->size);
        if (ret != LIBBPF_PERF_EVENT_CONT) {
            return ret;
        }
    } else if (e->header.type == PERF_RECORD_LOST) {
        struct lost *lost = reinterpret_cast<struct lost *>(e);

        info("lost %lu events", lost->lost);
    } else {
        info("unknown event type=%d size=%d", e->header.type, e->header.size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

int
dump::perf_event_mmap() {
    for (int i = 0; i < nr_cpus_; i++)
        if (_perf_event_mmap_header(pmu_fds_[i], &headers_[i]) < 0)
            throw std::string("failed perf_event_mmap_header index:" +
                                     std::to_string(i));
    return SUCCESS;
}

int
dump::_perf_event_mmap_header(int fd, struct perf_event_mmap_page **header) {

    void *base;
    int mmap_size;

    page_size_ = getpagesize();
    mmap_size  = page_size_ * (page_cnt_ + 1);

    base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        throw std::string("mmap err");
    }

    *header = reinterpret_cast<struct perf_event_mmap_page *>(base);
    return SUCCESS;
}

enum bpf_perf_event_ret
dump::perf_event_poller_multi() {
    enum bpf_perf_event_ret ret;

    struct pollfd *pfds;
    void *buf  = NULL;
    size_t len = 0;

    pfds = new struct pollfd[nr_cpus_];
    if (!pfds) {
        return LIBBPF_PERF_EVENT_ERROR;
    }

    for (int i = 0; i < nr_cpus_; i++) {
        pfds[i].fd     = pmu_fds_[i];
        pfds[i].events = POLLIN;
    }

    verbose_ = config_.verbose;
    while (!done_) {
        poll(pfds, nr_cpus_, 1000);
        for (int i = 0; i < nr_cpus_; i++) {
            if (!pfds[i].revents) {
                continue;
            }

            ret = bpf_perf_event_read_simple(
                headers_[i],
                page_cnt_ * page_size_,
                page_size_,
                &buf,
                &len,
                _bpf_perf_event_print,
                reinterpret_cast<void *>(_print_bpf_output));
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
dump::open_pcap() {

    pd_ = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pd_) {
        throw std::string("pcap_open_dead failed");
    }

    pdumper_ = pcap_dump_open(pd_, config_.dumpfile.c_str());
    if (!pdumper_) {
        throw std::string("pcap_dump_open failed");
    }

    return SUCCESS;
}

void
dump::close_pcap() {
    pcap_dump_close(pdumper_);
    pcap_close(pd_);
}

void
dump::print_result() {
    info("");
    info(
        "%u packet samples stored in %s", pcap_pkts_, config_.dumpfile.c_str());
}
int
dump::attach() {
    return SUCCESS;
}
int
dump::detach() {

    return SUCCESS;
}

void
dump::test_bpf_perf_event() {

    struct perf_event_attr attr = {
        .sample_type   = PERF_SAMPLE_RAW,
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    for (int i = 0; i < nr_cpus_; i++) {
        int key = i;

        pmu_fds_[i] = _sys_perf_event_open(
            attr, -1 /*pid*/, i /*cpu*/, -1 /*group_fd*/, 0);

        assert(pmu_fds_[i] >= 0);
        assert(bpf_map_update_elem(map_fd_, &key, &pmu_fds_[i], BPF_ANY) == 0);
        ioctl(pmu_fds_[i], PERF_EVENT_IOC_ENABLE, 0);
    }
}
