#ifndef __DEFINE_KERN_H
#define __DEFINE_KERN_H

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#ifndef memcpy
#define memcpy(dst, src, n) __builtin_memcpy((dst), (src), (n))
#endif

#endif /* end of include guard */
