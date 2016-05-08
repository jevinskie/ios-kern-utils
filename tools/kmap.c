/*
 * kmap.c - Display a listing of the kernel memory mappings
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
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

int main()
{
    task_t kernel_task;

    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        fprintf(stderr, "[!] Failed to get kernel task\n");
        return -1;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0;
    size_t displaysize;
    char scale;
    char curR, curW, curX, maxR, maxW, maxX;

    while (1)
    {
        // get next memory region
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
        }

        // protection
        curR = (info.protection) & VM_PROT_READ ? 'r' : '-';
        curW = (info.protection) & VM_PROT_WRITE ? 'w' : '-';
        curX = (info.protection) & VM_PROT_EXECUTE ? 'x' : '-';
        maxR = (info.max_protection) & VM_PROT_READ ? 'r' : '-';
        maxW = (info.max_protection) & VM_PROT_WRITE ? 'w' : '-';
        maxX = (info.max_protection) & VM_PROT_EXECUTE ? 'x' : '-';

        printf(ADDR "-" ADDR " [%5zu%c] %c%c%c/%c%c%c\n",
               addr, addr+size, displaysize, scale,
               curR, curW, curX, maxR, maxW, maxX);

        addr += size;
    }

    return 0;
}
