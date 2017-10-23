/*
 * kmap.c - Display a listing of the kernel memory mappings
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <limits.h>             // UINT_MAX
#include <stdbool.h>            // bool, true, false
#include <stdio.h>              // printf, fprintf, stderr

#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/mach_types.h>    // task_t
#include <mach/message.h>       // mach_msg_type_number_t
#include <mach/vm_inherit.h>    // VM_INHERIT_*
#include <mach/vm_map.h>        // vm_region_recurse_64
#include <mach/vm_prot.h>       // VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE
#include <mach/vm_region.h>     // VM_REGION_SUBMAP_INFO_COUNT_64, vm_region_info_t, vm_region_submap_info_data_64_t
#include <mach/vm_types.h>      // vm_address_t, vm_size_t

#include "arch.h"               // ADDR
#include "debug.h"              // slow, verbose
#include "libkern.h"            // get_kernel_task

#define VM_KERN_MEMORY_NONE                 0
#define VM_KERN_MEMORY_OSFMK                1
#define VM_KERN_MEMORY_BSD                  2
#define VM_KERN_MEMORY_IOKIT                3
#define VM_KERN_MEMORY_LIBKERN              4
#define VM_KERN_MEMORY_OSKEXT               5
#define VM_KERN_MEMORY_KEXT                 6
#define VM_KERN_MEMORY_IPC                  7
#define VM_KERN_MEMORY_STACK                8
#define VM_KERN_MEMORY_CPU                  9
#define VM_KERN_MEMORY_PMAP                10
#define VM_KERN_MEMORY_PTE                 11
#define VM_KERN_MEMORY_ZONE                12
#define VM_KERN_MEMORY_KALLOC              13
#define VM_KERN_MEMORY_COMPRESSOR          14
#define VM_KERN_MEMORY_COMPRESSED_DATA     15
#define VM_KERN_MEMORY_PHANTOM_CACHE       16
#define VM_KERN_MEMORY_WAITQ               17
#define VM_KERN_MEMORY_DIAG                18
#define VM_KERN_MEMORY_LOG                 19
#define VM_KERN_MEMORY_FILE                20
#define VM_KERN_MEMORY_MBUF                21
#define VM_KERN_MEMORY_UBC                 22
#define VM_KERN_MEMORY_SECURITY            23
#define VM_KERN_MEMORY_MLOCK               24
#define VM_KERN_MEMORY_REASON              25
#define VM_KERN_MEMORY_SKYWALK             26
#define VM_KERN_MEMORY_LTABLE              27
#define VM_KERN_MEMORY_FIRST_DYNAMIC       28

static const char* kern_tag(uint32_t tag)
{
    switch(tag)
    {
        case VM_KERN_MEMORY_NONE:               return "";
        case VM_KERN_MEMORY_OSFMK:              return "OSFMK";
        case VM_KERN_MEMORY_BSD:                return "BSD";
        case VM_KERN_MEMORY_IOKIT:              return "IOKit";
        case VM_KERN_MEMORY_LIBKERN:            return "Libkern";
        case VM_KERN_MEMORY_OSKEXT:             return "OSKext";
        case VM_KERN_MEMORY_KEXT:               return "Kext";
        case VM_KERN_MEMORY_IPC:                return "IPC";
        case VM_KERN_MEMORY_STACK:              return "Stack";
        case VM_KERN_MEMORY_CPU:                return "CPU management";
        case VM_KERN_MEMORY_PMAP:               return "Page map";
        case VM_KERN_MEMORY_PTE:                return "Page table";
        case VM_KERN_MEMORY_ZONE:               return "Zalloc";
        case VM_KERN_MEMORY_KALLOC:             return "Kalloc";
        case VM_KERN_MEMORY_COMPRESSOR:         return "VM compressor";
        case VM_KERN_MEMORY_COMPRESSED_DATA:    return "TODO";
        case VM_KERN_MEMORY_PHANTOM_CACHE:      return "Phantom (thrashing)";
        case VM_KERN_MEMORY_WAITQ:              return "TODO";
        case VM_KERN_MEMORY_DIAG:               return "Diagnostics";
        case VM_KERN_MEMORY_LOG:                return "TODO";
        case VM_KERN_MEMORY_FILE:               return "File handling";
        case VM_KERN_MEMORY_MBUF:               return "TODO";
        case VM_KERN_MEMORY_UBC:                return "TODO";
        case VM_KERN_MEMORY_SECURITY:           return "Security/MACF";
        case VM_KERN_MEMORY_MLOCK:              return "TODO";
        case VM_KERN_MEMORY_REASON:             return "TODO";
        case VM_KERN_MEMORY_SKYWALK:            return "Skywalk";
        case VM_KERN_MEMORY_LTABLE:             return "TODO";
    }

    return tag >= VM_KERN_MEMORY_FIRST_DYNAMIC ? "(dynamic)" : "???";
}

static const char* share_mode(char mode)
{
    switch(mode)
    {
        case SM_COW:                return "cow";
        case SM_PRIVATE:            return "prv";
        case SM_EMPTY:              return "nul";
        case SM_SHARED:             return "shm";
        case SM_TRUESHARED:         return "tru";
        case SM_PRIVATE_ALIASED:    return "p/a";
        case SM_SHARED_ALIASED:     return "s/a";
        case SM_LARGE_PAGE:         return "big";
    }
    return "???";
}

static const char* inheritance(vm_inherit_t inh)
{
    switch(inh)
    {
        case VM_INHERIT_SHARE:          return "sh";
        case VM_INHERIT_COPY:           return "cp";
        case VM_INHERIT_NONE:           return "--";
        case VM_INHERIT_DONATE_COPY:    return "dn";
    }
    return "??";
}

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage: %s [-h] [-v [-d]] [-e]\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -e  Extended output (print all information available)\n"
                    "    -g  Show gaps between regions\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

static void print_range(task_t kernel_task, bool extended, bool gaps, unsigned int level, vm_address_t min, vm_address_t max)
{
    vm_region_submap_info_data_64_t info;
    vm_address_t last_addr = min;
    vm_size_t size, last_size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth;
    size_t displaysize, last_displaysize;
    char scale, last_scale;
    char curA, curR, curW, curX, maxA, maxR, maxW, maxX;

    for(vm_address_t addr = min; 1; addr += size)
    {
        // get next memory region
        depth = level;
        if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
        {
            break;
        }
        if(addr >= max)
        {
            addr = max;
        }

        if(gaps)
        {
            if(last_addr != 0)
            {
                last_size = addr - last_addr;
                if(last_size > 0)
                {
                    last_scale = 'K';
                    last_displaysize = last_size / 1024;
                    if(last_displaysize > 4096)
                    {
                        last_scale = 'M';
                        last_displaysize /= 1024;
                        if(last_displaysize > 4096)
                        {
                            last_scale = 'G';
                            last_displaysize /= 1024;
                        }
                    }
                    printf("%*s [%4zu%c]\n"
                           , (int)(4 * sizeof(void*) + 1 + (extended ? 4 : 0)), ""
                           , last_displaysize, last_scale
                    );
                }
            }
            last_addr = addr + size;
        }

        if(addr >= max)
        {
            break;
        }

        // size
        scale = 'K';
        displaysize = size / 1024;
        if(displaysize > 4096)
        {
            scale = 'M';
            displaysize /= 1024;
            if(displaysize > 4096)
            {
                scale = 'G';
                displaysize /= 1024;
            }
        }

        // protection
        curA = (info.protection) & ~(VM_PROT_ALL) ? '+' : '-';
        curR = (info.protection) & VM_PROT_READ ? 'r' : '-';
        curW = (info.protection) & VM_PROT_WRITE ? 'w' : '-';
        curX = (info.protection) & VM_PROT_EXECUTE ? 'x' : '-';
        maxA = (info.max_protection) & ~(VM_PROT_ALL) ? '+' : '-';
        maxR = (info.max_protection) & VM_PROT_READ ? 'r' : '-';
        maxW = (info.max_protection) & VM_PROT_WRITE ? 'w' : '-';
        maxX = (info.max_protection) & VM_PROT_EXECUTE ? 'x' : '-';

        if(extended)
        {
            printf("%*s" ADDR "-" ADDR "%*s" " [%4zu%c] %c%c%c%c/%c%c%c%c [%s %s %s] %016llx [%u %u %hu %hhu %hu] %08x/%08x:<%10u> %u,%u {%10u,%10u} %s\n"
                   , 4 * level, "", addr, addr+size, 4 * (1 - level), ""
                   , displaysize, scale
                   , curA, curR, curW, curX
                   , maxA, maxR, maxW, maxX
                   , info.is_submap ? "map" : depth > 0 ? "sub" : "mem", share_mode(info.share_mode), inheritance(info.inheritance), info.offset
                   , info.behavior, info.pages_reusable, info.user_wired_count, info.external_pager, info.shadow_depth // these should all be 0
                   , info.user_tag, info.object_id, info.ref_count
                   , info.pages_swapped_out, info.pages_shared_now_private, info.pages_resident, info.pages_dirtied
                   , kern_tag(info.user_tag)
            );
        }
        else
        {
            printf(ADDR "-" ADDR " [%4zu%c] %c%c%c/%c%c%c\n"
                   , addr, addr + size, displaysize, scale
                   , curR, curW, curX, maxR, maxW, maxX);
        }

        if(info.is_submap)
        {
            print_range(kernel_task, extended, gaps, level + 1, addr, addr + size);
        }
    }
}

int main(int argc, const char **argv)
{
    bool extended = false,
         gaps     = false;

    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        if(strcmp(argv[i], "-d") == 0)
        {
            slow = true;
        }
        else if(strcmp(argv[i], "-v") == 0)
        {
            verbose = true;
        }
        else if(strcmp(argv[i], "-e") == 0)
        {
            extended = true;
        }
        else if(strcmp(argv[i], "-g") == 0)
        {
            gaps = true;
        }
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    task_t kernel_task;
    KERNEL_TASK_OR_GTFO(kernel_task);

    print_range(kernel_task, extended, gaps, 0, 0, ~0);

    return 0;
}
