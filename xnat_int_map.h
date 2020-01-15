#ifndef __NAT_INT_KERN_H
#define __NAT_INT_KERN_H

// #define PROG(F) SEC(#F) int bpf_func_##F

// enum {
//     ARP = 1,
//     IP,
//     IPV6,
// };

// struct bpf_map_def SEC("maps") prog_map = {
//     .type        = BPF_MAP_TYPE_PROG_ARRAY,
//     .key_size    = sizeof(__u32),
//     .value_size  = sizeof(__u32),
//     .max_entries = 8,
// };

struct bpf_map_def SEC("maps") tx_map = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 50,
};

struct bpf_map_def SEC("maps") redirect_params = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = ETH_ALEN,
    .value_size  = ETH_ALEN,
    .max_entries = 50,
};

struct bpf_map_def SEC("maps") nat_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct nm_k),
    .value_size  = sizeof(struct nat_table),
    .max_entries = 100,
};

struct bpf_map_def SEC("maps") if_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct ifinfo),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") port_pool_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__be16),
    .value_size  = sizeof(__be16),
    .max_entries = 60000,
};

struct bpf_map_def SEC("maps") freelist_map = {
    .type        = BPF_MAP_TYPE_STACK,
    .key_size    = 0,
    .value_size  = sizeof(__be16),
    .max_entries = 60000,
    .map_flags   = 0,
};

#endif /* end of include guard */
