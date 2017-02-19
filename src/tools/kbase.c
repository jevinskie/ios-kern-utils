/*
 * kbase.c - Print kernel base
 *
 * Copyright (c) 2017 Siguza
 */

#include <stdio.h>              // printf, fprintf, stderr
#include <stdlib.h>             // malloc, free

#include <mach/vm_region.h>     // SM_*, VM_REGION_SUBMAP_INFO_COUNT_64, vm_region_info_t, vm_region_submap_info_data_64_t
#include <mach/vm_map.h>        // vm_region_recurse_64
#include <mach/vm_types.h>      // vm_address_t

#include "arch.h"               // ADDR
#include "debug.h"              // slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO, get_kernel_task, get_base_region, kernel_read

static void print_all_candidates(void)
{
    region_t *reg = get_base_region();
    if(reg == NULL)
    {
        return;
    }
    vm_address_t regstart = reg->addr,
                 regend   = reg->addr + reg->size;

    task_t kernel_task;
    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        return;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;

    for(vm_address_t addr = 0; 1; addr += size)
    {
        DEBUG("Searching for next region at " ADDR "...", addr);
        depth = 0xff;
        if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
        {
            break;
        }

        if(info.share_mode == SM_PRIVATE && !info.is_submap)
        {
            DEBUG("Found private region " ADDR "-" ADDR ", dumping and scanning it...", addr, addr + size);
            vm_address_t *buf = malloc(size);
            if(buf == NULL)
            {
                DEBUG("Memory allocation error, returning 0.");
                return;
            }
            if(kernel_read(addr, size, buf) != size)
            {
                DEBUG("Kernel I/O error, returning 0.");
                free(buf);
                return;
            }
            for(vm_address_t *p = buf, *last = (vm_address_t*)&((char*)p)[size]; p < last; ++p)
            {
                if(*p >= regstart && *p < regend)
                {
                    printf(ADDR "\n", *p);
                }
            }
            free(buf);
        }
    }
}

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage: %s [-h] [-v [-d]] [-e]\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -p  Print all pointers to base region, but do not read from it\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

int main(int argc, const char **argv)
{
    bool print = false;

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
        else if(strcmp(argv[i], "-p") == 0)
        {
            print = true;
        }
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if(print)
    {
        print_all_candidates();
    }
    else
    {
        vm_address_t kbase;
        KERNEL_BASE_OR_GTFO(kbase);
        printf(ADDR "\n", kbase);
    }

    return 0;
}
