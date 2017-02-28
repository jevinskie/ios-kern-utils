/*
 * arch.h - Code to deal with different architectures.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef ARCH_H
#define ARCH_H

#include <mach-o/loader.h>      // mach_header, mach_header_64, segment_command, segment_command_64

#define HAVE_TAGGED_REGIONS kCFCoreFoundationVersionNumber_iOS_8_x_Max
#define HAVE_REFACTORED_OSSTRING kCFCoreFoundationVersionNumber_iOS_9_x_Max

#if __LP64__
#   define IMAGE_OFFSET 0x2000
#   define MACH_TYPE CPU_TYPE_ARM64
#   define ADDR "%016lx"
#   define SIZE "%lu"
#   define MACH_HEADER_MAGIC MH_MAGIC_64
#   define MACH_LC_SEGMENT LC_SEGMENT_64
#   define KERNEL_SPACE 0x8000000000000000
    typedef struct mach_header_64 mach_hdr_t;
    typedef struct segment_command_64 mach_seg_t;
    typedef struct section_64 mach_sec_t;
#else
#   define IMAGE_OFFSET 0x1000
#   define MACH_TYPE CPU_TYPE_ARM
#   define ADDR "%08x"
#   define SIZE "%u"
#   define MACH_HEADER_MAGIC MH_MAGIC
#   define MACH_LC_SEGMENT LC_SEGMENT
#   define KERNEL_SPACE 0x80000000
    typedef struct mach_header mach_hdr_t;
    typedef struct segment_command mach_seg_t;
    typedef struct section mach_sec_t;
#endif
typedef struct load_command mach_lc_t;

#endif
