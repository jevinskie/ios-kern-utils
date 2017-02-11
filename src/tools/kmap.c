/*
 * kmap.c - Display a listing of the kernel memory mappings
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <stdio.h>              // printf, fprintf, stderr

#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/mach_types.h>    // task_t
#include <mach/message.h>       // mach_msg_type_number_t
#include <mach/vm_map.h>        // vm_region_recurse_64
#include <mach/vm_prot.h>       // VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE
#include <mach/vm_region.h>     // VM_REGION_SUBMAP_INFO_COUNT_64, vm_region_info_t, vm_region_submap_info_data_64_t
#include <mach/vm_types.h>      // vm_address_t, vm_size_t

#include "arch.h"               // ADDR
#include "libkern.h"            // get_kernel_task

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

int main(void)
{
    task_t kernel_task;

    KERNEL_TASK_OR_GTFO(kernel_task);

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth;
    size_t displaysize;
    char scale;
    char curR, curW, curX, maxR, maxW, maxX;

    for(vm_address_t addr = 0; 1; addr += size)
    {
        // get next memory region
        depth = 255;
        if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
        {
            break;
        }

        // size
        scale = 'K';
        displaysize = size / 1024;
        if(displaysize > 99999)
        {
            scale = 'M';
            displaysize /= 1024;
            if(displaysize > 99999)
            {
                scale = 'G';
                displaysize /= 1024;
            }
        }

        // protection
        curR = (info.protection) & VM_PROT_READ ? 'r' : '-';
        curW = (info.protection) & VM_PROT_WRITE ? 'w' : '-';
        curX = (info.protection) & VM_PROT_EXECUTE ? 'x' : '-';
        maxR = (info.max_protection) & VM_PROT_READ ? 'r' : '-';
        maxW = (info.max_protection) & VM_PROT_WRITE ? 'w' : '-';
        maxX = (info.max_protection) & VM_PROT_EXECUTE ? 'x' : '-';

        printf(ADDR "-" ADDR " [%5zu%c] %c%c%c/%c%c%c [%s %s]\n"
               , addr, addr+size, displaysize, scale
               , curR, curW, curX, maxR, maxW, maxX
               , info.user_tag > 0 ? "usr" : "krn", share_mode(info.share_mode));
    }

    return 0;
}
