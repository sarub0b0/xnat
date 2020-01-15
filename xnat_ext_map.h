#ifndef __NAT_EXT_KERN_H
#define __NAT_EXT_KERN_H

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

#endif /* end of include guard */
