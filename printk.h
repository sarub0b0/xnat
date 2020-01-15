#ifndef __BPF_PRINTK_H
#define __BPF_PRINTK_H

#undef bpf_printk
#ifdef DEBUG

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
#define bpf_printk(fmt...)
#endif

// #define err_map_update(errno, flags)                                        \
//     do {                                                                    \
//         switch (errno) {                                                    \
//             case E2BIG:                                                     \
//                 bpf_printk("ERR: the map reached the max entries limit");   \
//                 break;                                                      \
//             case EEXIST:                                                    \
//                 bpf_printk(                                                 \
//                     "ERR: the element with key already exists in the map"); \
//                 break;                                                      \
//             case ENOENT:                                                    \
//                 bpf_printk(                                                 \
//                     "ERR: the element with key doesn't exist in the map");  \
//                 break;                                                      \
//         }                                                                   \
//         switch (flags) {                                                    \
//             case BPF_ANY:                                                   \
//                 bpf_printk(" flags(BPF_ANY)\n");                            \
//                 break;                                                      \
//             case BPF_EXIST:                                                 \
//                 bpf_printk(" flags(BPF_EXIST)\n");                          \
//                 break;                                                      \
//             case BPF_NOEXIST:                                               \
//                 bpf_printk(" flags(BPF_NOEXIST)\n");                        \
//                 break;                                                      \
//         }                                                                   \
//     } while (0);

#endif
