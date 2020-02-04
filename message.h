#ifndef __MESSAGE_H
#define __MESSAGE_H

#include <stdio.h>
#define err(fmt...)                                               \
    do {                                                          \
        fprintf(stderr, "ERR: %s, line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, fmt);                                     \
        fprintf(stderr, "\n");                                    \
    } while (0)

#define warn(fmt...)               \
    do {                           \
        fprintf(stderr, "WARN: "); \
        fprintf(stderr, fmt);      \
        fprintf(stderr, "\n");     \
    } while (0)

#define info(fmt...)               \
    do {                           \
        fprintf(stdout, "INFO: "); \
        fprintf(stdout, fmt);      \
        fprintf(stdout, "\n");     \
    } while (0)

#endif /* end of include guard */
