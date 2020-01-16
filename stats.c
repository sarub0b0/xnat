#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <locale.h>

#include "stats.h"
#include "message.h"
#include "utils.h"

const char *map_name    = "stats_map";
const char *dev_name    = "xnat";
const char *pin_basedir = "/sys/fs/bpf";

const char *xdp_action_names[XDP_ACTION_MAX] = {
    [XDP_ABORTED]  = "XDP_ABORTED",
    [XDP_DROP]     = "XDP_DROP",
    [XDP_PASS]     = "XDP_PASS",
    [XDP_TX]       = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT",
};

struct record {
    uint64_t timestamp;
    struct datarec total;
};

struct stats_record {
    struct record stats[XDP_ACTION_MAX];
};

const char *action2str(uint32_t action) {
    if (action < XDP_ACTION_MAX) {
        return xdp_action_names[action];
    }
    return NULL;
}

#define NANOSEC_PER_SEC 1000000000
static uint64_t gettime(void) {
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        err("with clock_gettime! (%i)", res);
        exit(EXIT_FAIL);
    }
    return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p) {
    double ret      = 0;
    uint64_t period = 0;
    period          = r->timestamp - p->timestamp;
    if (period > 0) {
        ret = ((double) period / NANOSEC_PER_SEC);
    }
    return ret;
}

static inline void stats_print_header(void) {
    printf("%-12s\n", "XDP-action");
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
    struct record *rec, *prev;
    uint64_t packets, bytes;
    double period;
    double pps;
    double bps;

    stats_print_header();

    for (int i = 0; i < XDP_ACTION_MAX; i++) {
        char *fmt =
            "%-12s %'11lld pkts (%'10.0f pps) %'11lld Kbytes (%'6.0f Mbits/s) "
            "period:%f\n";

        const char *action = action2str(i);

        rec  = &stats_rec->stats[i];
        prev = &stats_prev->stats[i];

        period = calc_period(rec, prev);
        if (period == 0) {
            return;
        }

        packets = rec->total.rx_packets - prev->total.rx_packets;
        pps     = packets / period;

        bytes = rec->total.rx_bytes - prev->total.rx_bytes;
        bps   = (bytes * 8) / period / 1000000;

        printf(fmt,
               action,
               rec->total.rx_packets,
               pps,
               rec->total.rx_packets / 1000,
               bps,
               period);
    }
    printf("\n");
}
void map_get_value_array(int fd, uint32_t key, struct datarec *value) {

    if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed\n");
    }
}

void map_get_value_percpu_array(int fd, uint32_t key, struct datarec *value) {

    uint32_t nr_cpus = bpf_num_possible_cpus();
    struct datarec values[nr_cpus];
    uint64_t sum_bytes = 0;
    uint64_t sum_pkts  = 0;

    if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed\n");
        return;
    }
    for (int i = 0; i < nr_cpus; i++) {
        sum_pkts += values[i].rx_packets;
        sum_bytes += values[i].rx_bytes;
    }
    value->rx_packets = sum_pkts;
    value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd,
                        uint32_t map_type,
                        uint32_t key,
                        struct record *rec) {
    struct datarec value;

    rec->timestamp = gettime();

    switch (map_type) {
        case BPF_MAP_TYPE_ARRAY:
            map_get_value_array(fd, key, &value);
            break;
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            map_get_value_percpu_array(fd, key, &value);
            break;
        default:
            err("Unknown map_type(%u) cannot handle", map_type);
            return false;
    }

    rec->total.rx_packets = value.rx_packets;
    rec->total.rx_bytes   = value.rx_bytes;
    return true;
}

static void stats_collect(int map_fd,
                          uint32_t map_type,
                          struct stats_record *stats_rec) {
    for (int key = 0; key < XDP_ACTION_MAX; key++) {
        map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
    }
}

static int stats_poll(
    const char *pin_dir, int map_fd, int id, uint32_t map_type, int interval) {

    struct bpf_map_info info = {};
    struct stats_record prev, record = {};

    setlocale(LC_NUMERIC, "en_US");

    stats_collect(map_fd, map_type, &record);
    usleep(1000000 / 4);

    while (1) {
        prev = record;

        map_fd = open_bpf_map_file(pin_dir, map_name, &info);
        if (map_fd < 0) {
            return EXIT_FAIL_BPF;
        } else if (id != info.id) {
            info("BPF map %s changed its ID, restarting\n", map_name);
            close(map_fd);
            return 0;
        }

        stats_collect(map_fd, map_type, &record);
        stats_print(&record, &prev);
        sleep(interval);
    }
}

int main(int argc, char const *argv[]) {

    char pin_dir[PATH_MAX];
    struct bpf_map_info info = {0};
    int map_fd;
    int len;
    int err;

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, dev_name);
    if (len < 0) {
        err("creating pin dirname");
        return EXIT_FAIL_OPTION;
    }

    int interval = 2;
    while (1) {
        map_fd = open_bpf_map_file(pin_dir, map_name, &info);
        if (map_fd < 0) {
            fprintf(stderr, "ERR: bpf_map__fd failed. [%s]\n", map_name);
            return EXIT_FAIL_BPF;
        }

        printf("\nCollecting stats from BPF map\n");
        printf(
            " - BPF map (bpf_map_type:%d) id:%d name:%s key_size:%d "
            "value_size:%d "
            "max_entries:%d\n",
            info.type,
            info.id,
            info.name,
            info.key_size,
            info.value_size,
            info.max_entries);

        err = stats_poll(pin_dir, map_fd, info.id, info.type, interval);
        if (err < 0) {
            return err;
        }
    }
    return EXIT_OK;
}
