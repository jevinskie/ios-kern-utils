/*
 * libkern.c - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <stdlib.h>             // free, malloc
#include <string.h>             // memmem

#include <mach/host_priv.h>     // host_get_special_port
#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/mach_init.h>     // mach_host_self, mach_task_self
#include <mach/message.h>       // mach_msg_type_number_t
#include <mach/mach_error.h>    // mach_error_string
#include <mach/mach_traps.h>    // task_for_pid
#include <mach/mach_types.h>    // task_t
#include <mach/port.h>          // MACH_PORT_NULL, MACH_PORT_VALID
#include <mach/vm_prot.h>       // VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE
#include <mach/vm_region.h>     // SM_*, VM_REGION_SUBMAP_INFO_COUNT_64, vm_region_info_t, vm_region_submap_info_data_64_t
#include <mach/vm_map.h>        // vm_read_overwrite, vm_region_recurse_64, vm_write
#include <mach/vm_types.h>      // vm_address_t, vm_size_t
#include <mach-o/loader.h>      // MH_EXECUTE

#include "arch.h"               // IMAGE_OFFSET, MACH_TYPE, MACH_HEADER_MAGIC, mach_hdr_t
#include "debug.h"              // DEBUG
#include "mach-o.h"             // CMD_ITERATE

#include "libkern.h"

#define MAX_CHUNK_SIZE 0xFFF /* MIG limitation */

#define VERIFY_PORT(port, ret) \
do \
{ \
    if(MACH_PORT_VALID(port)) \
    { \
        if(ret == KERN_SUCCESS) \
        { \
            DEBUG("Success!"); \
        } \
        else \
        { \
            DEBUG("Got a valid port, but return value is 0x%08x (%s)", ret, mach_error_string(ret)); \
            ret = KERN_SUCCESS; \
        } \
    } \
    else \
    { \
        if(ret == KERN_SUCCESS) \
        { \
            DEBUG("Returned success, but port is invalid (0x%08x)", port); \
            ret = KERN_FAILURE; \
        } \
        else \
        { \
            DEBUG("Failure. Port: 0x%08x, return value: 0x%08x (%s)", port, ret, mach_error_string(ret)); \
        } \
    } \
} while(0)

kern_return_t get_kernel_task(task_t *task)
{
    static task_t kernel_task = MACH_PORT_NULL;
    static char initialized = 0;
    if(!initialized)
    {
        DEBUG("Getting kernel task...");
        DEBUG("Trying task_for_pid(0)...");
        kernel_task = MACH_PORT_NULL;
        kern_return_t ret = task_for_pid(mach_task_self(), 0, &kernel_task);
        VERIFY_PORT(kernel_task, ret);
        if(ret != KERN_SUCCESS)
        {
            // Try Pangu's special port
            DEBUG("Trying host_get_special_port(4)...");
            kernel_task = MACH_PORT_NULL;
            ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
            VERIFY_PORT(kernel_task, ret);
        }
        if(ret != KERN_SUCCESS)
        {
            DEBUG("Returning failure.");
            return ret;
        }
        DEBUG("Success, caching returned port.");
        initialized = 1;
        DEBUG("kernel_task = 0x%08x", kernel_task);
    }
    *task = kernel_task;
    return KERN_SUCCESS;
}

// 0 = true
// 1 = false
// 2 = fatal
static uint8_t is_kernel_header(mach_hdr_t *hdr)
{
    if(hdr->magic != MACH_HEADER_MAGIC)
    {
        return 1;
    }
    if(hdr->cputype != MACH_TYPE)
    {
        DEBUG("Found Mach-O, but for wrong architecture: 0x%x", hdr->cputype);
        return 2;
    }
    if(hdr->filetype != MH_EXECUTE)
    {
        DEBUG("Found Mach-O, but not MH_EXECUTE, skipping.");
        return 1;
    }
    DEBUG("Seems all good");
    return 0;
}

// Kernel Base: This is a long story.
//
// Obtaining the kernel slide/base address is non-trivial, even with access to
// the kernel task port. Using the vm_region_* APIs, however, one can iterate
// over its memory regions, which provides a starting point. Additionally, there
// is a special region (I call it the "base region"), within which the kernel is
// located.
//
//
// Some history:
//
// In Saelo's original code (working up to and including iOS 7), the base region
// would be uniquely identified by being larger than 1 GB. The kernel had a
// simple offset from the region's base address of 0x1000 bytes on 32-bit, and
// 0x2000 bytes on 64-bit.
//
// With iOS 8, the property of being larger than 1GB was no longer unique.
// Additionally, one had to check for ---/--- access permissions, which would
// again uniquely identify the base region. The kernel offset from its base
// address remained the same.
//
// With iOS 9, the kernel's offset from the region's base address was doubled
// for most (but seemingly not all) devices. I simply checked both 0x1000 and
// 0x2000 for 32-bit and 0x2000 and 0x4000 for 64-bit.
//
// Somewhere between iOS 9.0 and 9.1, the kernel started not having a fixed
// offset from the region's base address anymore. In addition to the fixed
// offset, it could have a multiple of 0x100000 added to its address, seemingly
// uncorrelated to the region's base address, as if it had an additional KASLR
// slide applied within the region. Also, the kernel's offset from the region's
// base address could be much larger than the kernel itself.
// I worked around this by first locating the base region, checking for the
// Mach-O magic, and simply adding 0x100000 to the address until I found it.
//
// With iOS 10, the base address identification was no longer sufficient, as
// another null mapping of 64GB size had popped up. So in addition to the other
// two, I added the criterium of a size smaller than 16GB.
// In addition to that, the part of the base region between its base address and
// the kernel base does no longer have to be mapped (that is, it's still part of
// the memory region, but trying to access it will cause a panic). This
// completely broke my workaround for iOS 9, and it's also the reason why both
// nonceEnabler and nvram_patcher don't work reliably. It's still possible to
// get it to work through luck, but that chance is pretty small.
//
//
// Current observations and ideas:
//
// The base region still exists, still contains the kernel, and is still
// uniquely identifiable, but more information is required before one should
// attempt to access it. One source this "more information" could be obtained
// from are other memory regions.
// A great many memory region outright panic the device when accessed. However,
// all those with share_mode == SM_PRIVATE never do that, i.e. can always be
// read from.
// My idea from there on is to iterate over all of these memory regions on a
// pointer-sized granularity, look for any value that falls within the base
// region, and take the lowest of those. From there on, I round down to the next
// lower multiple of 0x100000 and start looking for the header.

vm_address_t get_kernel_base(void)
{
    static vm_address_t kbase;
    static char initialized = 0;
    if(!initialized)
    {
        DEBUG("Getting kernel base address...");
        task_t kernel_task;
        if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
        {
            return 0;
        }

        vm_address_t segstart = 0,
                     segend = 0;
        vm_region_submap_info_data_64_t info;
        vm_size_t size;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        unsigned int depth = 0;

        DEBUG("Looping over kernel memory regions...");
        for(vm_address_t addr = 0; 1; addr += size)
        {
            DEBUG("Searching for next region at " ADDR "...", addr);
            depth = 0xff;
            if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
            {
                break;
            }
            DEBUG("Found region " ADDR "-" ADDR "with %c%c%c", addr, addr + size, (info.protection) & VM_PROT_READ ? 'r' : '-', (info.protection) & VM_PROT_WRITE ? 'w' : '-', (info.protection) & VM_PROT_EXECUTE ? 'x' : '-');

            if
            (
                (info.protection & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) == 0 &&
                size >       1024*1024*1024 &&
#ifdef __LP64__
                size <= 16ULL * 1024*1024*1024 && // this is always true for 32-bit
#endif
                info.share_mode == SM_EMPTY
            )
            {
                if(segstart == 0 && segend == 0)
                {
                    DEBUG("Found a matching memory region.");
                    segstart = addr;
                    segend = addr + size;
                }
                else
                {
                    DEBUG("Found more than one matching memory region, returning 0.");
                    return 0;
                }
            }
        }

        if(segstart == 0)
        {
            DEBUG("Found no matching region, returning 0.");
            return 0;
        }
        if(segend < segstart)
        {
            DEBUG("Matching region has overflowing size, returning 0.");
            return 0;
        }
        DEBUG("Base region is at " ADDR "-" ADDR ".", segstart, segend);

        DEBUG("Looking for a pointer to it...");
        vm_address_t ptr = ~0;
        for(vm_address_t addr = 0; 1; addr += size)
        {
            DEBUG("Searching for next region at " ADDR "...", addr);
            depth = 0xff;
            if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
            {
                break;
            }

            if(info.share_mode == SM_PRIVATE)
            {
                DEBUG("Found private region " ADDR "-" ADDR ", dumping and scanning it...", addr, addr + size);
                vm_address_t *buf = malloc(size);
                if(buf == NULL)
                {
                    DEBUG("Memory allocation error, returning 0.");
                    return 0;
                }
                if(kernel_read(addr, size, buf) != size)
                {
                    DEBUG("Kernel I/O error, returning 0.");
                    free(buf);
                    return 0;
                }
                for(vm_address_t *p = buf, *last = (vm_address_t*)&((char*)p)[size]; p < last; ++p)
                {
                    if(*p >= segstart && *p < segend)
                    {
                        ptr = *p;
                        DEBUG("Candidate: " ADDR, ptr);
                    }
                }
                free(buf);
            }
        }

        if(ptr < segstart || ptr >= segend)
        {
            DEBUG("Found no valid pointer to base region, returning 0.");
            return 0;
        }
        DEBUG("Lowest pointer to base region: " ADDR, ptr);

        for(vm_address_t addr = (ptr >> 20) << 20; addr >= segstart; addr -= 0x100000)
        {
            mach_hdr_t hdr;
            vm_address_t haddr;

            haddr = addr + 2 * IMAGE_OFFSET;
            DEBUG("Looking for mach header at " ADDR "...", haddr);
            if(kernel_read(haddr, sizeof(hdr), &hdr) != sizeof(hdr))
            {
                DEBUG("Kernel I/O error, returning 0.");
                return 0;
            }

            uint8_t bad = is_kernel_header(&hdr);
            if(bad == 1)
            {
                haddr = addr + IMAGE_OFFSET;
                DEBUG("Looking for mach header at " ADDR "...", haddr);
                if(kernel_read(haddr, sizeof(hdr), &hdr) != sizeof(hdr))
                {
                    DEBUG("Kernel I/O error, returning 0.");
                    return 0;
                }
                bad = is_kernel_header(&hdr);
                if(bad == 1)
                {
                    continue;
                }
            }
            if(bad == 0)
            {
                DEBUG("Doing sanity-checks...");
                void *cmds = malloc(hdr.sizeofcmds);
                if(cmds == NULL)
                {
                    DEBUG("Memory allocation error, returning 0.");
                    return 0;
                }
                if(kernel_read(haddr + sizeof(hdr), hdr.sizeofcmds, cmds) != hdr.sizeofcmds)
                {
                    DEBUG("Kernel I/O error, returning 0.");
                    free(cmds);
                    return 0;
                }
                bad = 2;
                for(struct load_command *cmd = (struct load_command*)cmds, *end = (struct load_command*)&((char*)cmd)[hdr.sizeofcmds]; cmd < end; cmd = (struct load_command*)&((char*)cmd)[cmd->cmdsize])
                {
                    switch(cmd->cmd)
                    {
                        case MACH_LC_SEGMENT:
                            {
                                mach_seg_t *seg = (mach_seg_t*)cmd;
                                if(seg->vmaddr >=
#ifdef __LP64__
                                    0xffffff0000000000
#else
                                    0x80000000
#endif
                                )
                                {
                                    break;
                                }
                                // else fall through
                            }
                        case LC_LOAD_DYLIB:
                            DEBUG("Found userland binary, skipping.");
                            free(cmds);
                            goto next;
                        case LC_UNIXTHREAD:
                            bad = 0;
                            break;
                    }
                }
                free(cmds);
            }
            if(bad >= 2)
            {
                DEBUG("Bad header, returning 0.");
                return 0;
            }
            DEBUG("Got kernel base address, caching it.");
            kbase = haddr;
            initialized = 1;
            DEBUG("kernel_base = " ADDR, kbase);
            break;

            next:;
        }
    }
    return kbase;
}

vm_size_t kernel_read(vm_address_t addr, vm_size_t size, void *buf)
{
    DEBUG("Reading kernel bytes " ADDR "-" ADDR, addr, addr + size);
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size,
              bytes_read = 0;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_read_overwrite(kernel_task, addr, size, (vm_address_t)&((char*)buf)[bytes_read], &size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            DEBUG("vm_read error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }

    return bytes_read;
}

vm_size_t kernel_write(vm_address_t addr, vm_size_t size, void *buf)
{
    DEBUG("Writing to kernel at " ADDR "-" ADDR, addr, addr + size);
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size;
    vm_size_t bytes_written = 0;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_write(kernel_task, addr, (vm_offset_t)&((char*)buf)[bytes_written], size);
        if(ret != KERN_SUCCESS)
        {
            DEBUG("vm_write error: %s", mach_error_string(ret));
            break;
        }
        bytes_written += size;
        addr += size;
    }

    return bytes_written;
}

vm_address_t kernel_find(vm_address_t addr, vm_size_t len, void *buf, size_t size)
{
    vm_address_t ret = 0;
    unsigned char* b = malloc(len);
    if(b)
    {
        // TODO reading in chunks would probably be better
        if(kernel_read(addr, len, b))
        {
            void *ptr = memmem(b, len, buf, size);
            if(ptr)
            {
                ret = addr + ((char*)ptr - (char*)b);
            }
        }
        free(b);
    }
    return ret;
}
