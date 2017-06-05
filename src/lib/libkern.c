/*
 * libkern.c - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <limits.h>             // UINT_MAX
#include <stdio.h>              // fprintf, snprintf
#include <stdlib.h>             // free, malloc, random, srandom
#include <string.h>             // memmem
#include <time.h>               // time
#include <unistd.h>             // getpid

#include <mach/mach.h>          // Everything mach
#include <mach-o/loader.h>      // MH_EXECUTE

#include <CoreFoundation/CoreFoundation.h> // CF*

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
    static bool initialized = false;
    if(!initialized)
    {
        DEBUG("Getting kernel task...");
        kern_return_t ret;
        kernel_task = MACH_PORT_NULL;
        DEBUG("Trying task_for_pid(0)...");
        ret = task_for_pid(mach_task_self(), 0, &kernel_task);
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
        initialized = true;
        DEBUG("kernel_task = 0x%08x", kernel_task);
    }
    *task = kernel_task;
    return KERN_SUCCESS;
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
// all those with share_mode == SM_PRIVATE && !is_submap never do that,
// i.e. can always be read from.
// My idea from there on is to iterate over all of these memory regions on a
// pointer-sized granularity, look for any value that falls within the base
// region, and take the lowest of those. From there on, I round down to the next
// lower multiple of 0x100000 and start looking for the header.

#if 0
typedef struct
{
    vm_address_t addr;
    vm_size_t size;
} region_t;

region_t* get_base_region(void)
{
    static bool initialized = false;
    static region_t region = // allows us to return a pointer
    {
        .addr = 0,
        .size = 0,
    };
    if(!initialized)
    {
        DEBUG("Getting base region address...");
        task_t kernel_task;
        if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
        {
            return NULL;
        }

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
                if(region.addr == 0 && region.size == 0)
                {
                    DEBUG("Found a matching memory region.");
                    region.addr = addr;
                    region.size = size;
                }
                else
                {
                    DEBUG("Found more than one matching memory region, returning NULL.");
                    return NULL;
                }
            }
        }

        if(region.addr == 0)
        {
            DEBUG("Found no matching region, returning NULL.");
            return NULL;
        }
        if(region.addr + region.size < region.addr)
        {
            DEBUG("Base region has overflowing size, returning NULL.");
            return NULL;
        }
        DEBUG("Base region is at " ADDR "-" ADDR ".", region.addr, region.addr + region.size);
        initialized = true;
    }
    return &region;
}

typedef bool (*foreach_callback_t) (vm_address_t);

vm_address_t foreach_ptr_to_base_region(foreach_callback_t cb)
{
    region_t *reg = get_base_region();
    if(reg == NULL)
    {
        return 0;
    }
    vm_address_t regstart = reg->addr,
                 regend   = reg->addr + reg->size;

    task_t kernel_task;
    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        return 0;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;

    DEBUG("Looking for a pointer to base region...");
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
            char *buf = malloc(size);
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
            DEBUG("Looking for stack frames...");
            for(vm_size_t off = 0; off < (size - sizeof(void*)); off += sizeof(void*))
            {
                vm_size_t cur = off;
                size_t len = 0;
                vm_address_t lowest = ~0;
                do
                {
                    vm_address_t fp = ((vm_address_t*)&buf[cur])[0],
                                 lr = ((vm_address_t*)&buf[cur])[1];
                    if(lr > regstart && lr < regend) // DEBUG-XXX
                    {
                        DEBUG(ADDR " fp: " ADDR " lr: " ADDR, addr + cur, fp, lr);
                    }
                    if
                    (
                        fp > addr + cur + sizeof(void*) && fp < addr + size - sizeof(void*) &&
                        lr > regstart && lr < regend // absolute < and > are intentional
                    )
                    {
                        DEBUG(ADDR " fp: " ADDR " lr: " ADDR, addr + cur, fp, lr);
                        if(lr < lowest)
                        {
                            lowest = lr;
                        }
                        cur = fp - addr;
                        ++len;
                    }
                    else
                    {
                        if(len >= 5 && cb(lowest)) // threshold of 5 frames
                        {
                            free(buf);
                            return lowest;
                        }
                        break;
                    }
                } while(true);
            }
            free(buf);
        }
    }
    DEBUG("Callback never returned true, returning 0.");
    return 0;
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

static bool get_kernel_base_cb(vm_address_t addr)
{
    DEBUG("Candidate: " ADDR, addr);
    return true; // accept first candidate
}

vm_address_t get_kernel_base(void)
{
    static vm_address_t kbase;
    static bool initialized = false;
    if(!initialized)
    {
        DEBUG("Getting kernel base address...");

        vm_address_t ptr = foreach_ptr_to_base_region(&get_kernel_base_cb);
        if(ptr == 0)
        {
            return 0;
        }

        // Can omit NULL check here because in that case,
        // foreach_ptr_to_base_region() would've returned 0.
        vm_address_t regstart = get_base_region()->addr;

        DEBUG("Lowest pointer to base region: " ADDR, ptr);
        for(vm_address_t addr = (ptr >> 20) << 20; addr >= regstart; addr -= 0x100000)
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
            initialized = true;
            DEBUG("kernel_base = " ADDR, kbase);
            break;

            next:;
        }
    }
    return kbase;
}
#endif

// true = continue, false = abort
typedef bool (*kernel_region_callback_t) (vm_address_t, vm_size_t, vm_region_submap_info_data_64_t*, void*);

// true = success, false = failure
static bool foreach_kernel_region(kernel_region_callback_t cb, void *arg)
{
    DEBUG("Looping over kernel memory regions...");
    task_t kernel_task;
    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        return false;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth;
    for(vm_address_t addr = 0; 1; addr += size)
    {
        DEBUG("Searching for next region at " ADDR "...", addr);
        depth = UINT_MAX;
        if(vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS)
        {
            break;
        }
        if(!cb(addr, size, &info, arg))
        {
            return false;
        }
    }

    return true;
}

#define CB_NUM_VTABS 2

typedef struct
{
    vm_address_t regstart;
    vm_address_t regend;
    vm_address_t vtab[CB_NUM_VTABS]; // OSString, OSSymbol
    vm_address_t lowest;
} get_kernel_base_ios9_cb_args_t;

typedef struct
{
    vm_address_t vtab;
    int          retainCount;
    unsigned int flags;
    unsigned int length;
    vm_address_t string;
} OSString9;

typedef struct
{
    vm_address_t vtab;
    int          retainCount;
    unsigned int flags:14;
    unsigned int length:18;
    vm_address_t string;
} OSString10;

enum
{
    kOSStringNoCopy = 0x00000001,
};

#define VM_KERN_MEMORY_ZONE 12

static bool get_kernel_base_ios9_cb(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_ios9_cb_args_t *args = arg;
    if(info->user_tag == VM_KERN_MEMORY_ZONE)
    {
        DEBUG("Found zalloc region " ADDR "-" ADDR ", dumping and scanning it...", addr, addr + size);
        char *mem = malloc(size);
        if(mem == NULL)
        {
            DEBUG("Memory allocation error, aborting.");
            return false;
        }
        if(kernel_read(addr, size, mem) != size)
        {
            DEBUG("Kernel I/O error, aborting.");
            free(mem);
            return false;
        }

        for(size_t off = 0; off < size - sizeof(OSString9); off += sizeof(vm_address_t))
        {
            vm_address_t vtab;
            int          retainCount;
            unsigned int flags;
            unsigned int length;
            vm_address_t string;
            if(kCFCoreFoundationVersionNumber > HAVE_REFACTORED_OSSTRING)
            {
                OSString10 *osstr = (OSString10*)(&mem[off]);
                vtab        = osstr->vtab;
                retainCount = osstr->retainCount;
                flags       = osstr->flags;
                length      = osstr->length;
                string      = osstr->string;
            }
            else
            {
                OSString9 *osstr = (OSString9*)(&mem[off]);
                vtab        = osstr->vtab;
                retainCount = osstr->retainCount;
                flags       = osstr->flags;
                length      = osstr->length;
                string      = osstr->string;
            }
            if
            (
                retainCount == 0x10001                           && // 0x10000 is a tag, not the actual count
                flags == kOSStringNoCopy                         && // referenced, not copied
                length > 6              && length < 100          && // reasonable length
                vtab   > args->regstart && vtab   < args->regend && // vtab within base region
                string > args->regstart && string < args->regend    // string within base region
            )
            {
                DEBUG("Found OSString at " ADDR, (vm_address_t)(addr + off));
                if(verbose)
                {
                    fprintf(stderr, "OSString:\n"
                                    "{\n"
                                    "    vtab         = " ADDR "\n"
                                    "    retainCount  = %d\n"
                                    "    flags        = %u\n"
                                    "    length       = %u\n"
                                    "    string       = " ADDR "\n"
                                    "}\n"
                                    , vtab, retainCount, flags, length, string);
                }
                for(size_t i = 0; i < CB_NUM_VTABS; ++i)
                {
                    if(args->vtab[i] == 0)
                    {
                        DEBUG("Adding vtab to list...");
                        args->vtab[i] = vtab;
                        goto good;
                    }
                    else if(args->vtab[i] == vtab)
                    {
                        DEBUG("Known vtab, skipping.");
                        goto good;
                    }
                }
                DEBUG("Found more than %u different vtabs, aborting.", CB_NUM_VTABS);
                free(mem);
                return false;

                good:;
                vm_address_t lower = vtab > string ? string : vtab;
                if(args->lowest == 0 || args->lowest > lower)
                {
                    args->lowest = lower;
                }
            }
        }
        free(mem);
    }
    return true;
}

static vm_address_t get_kernel_base_ios9(vm_address_t regstart, vm_address_t regend)
{
    get_kernel_base_ios9_cb_args_t args =
    {
        .regstart = regstart,
        .regend = regend,
        .vtab = {0},
        .lowest = 0,
    };
    if(!foreach_kernel_region(&get_kernel_base_ios9_cb, &args))
    {
        return 0;
    }
    if(args.lowest == 0)
    {
        DEBUG("Failed to find any OSString, returning 0.");
        return 0;
    }

    DEBUG("Starting at " ADDR ", searching backwards...", args.lowest);
    for(vm_address_t addr = ((args.lowest >> 20) << 20) +
#ifdef __LP64__
            2 * IMAGE_OFFSET    // 0x4000 for 64-bit on >=9.0
#else
            IMAGE_OFFSET        // 0x1000 for 32-bit, regardless of OS version
#endif
        ; addr > regstart; addr -= 0x100000)
    {
        mach_hdr_t hdr;
        DEBUG("Looking for mach header at " ADDR "...", addr);
        if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
        {
            DEBUG("Kernel I/O error, returning 0.");
            return 0;
        }
        if(hdr.magic == MACH_HEADER_MAGIC && hdr.filetype == MH_EXECUTE)
        {
            DEBUG("Found Mach-O of type MH_EXECUTE at " ADDR ", returning success.", addr);
            return addr;
        }
    }

    DEBUG("Found no mach header, returning 0.");
    return 0;
}

static vm_address_t get_kernel_base_ios8(vm_address_t regstart)
{
    // things used to be so simple...
    vm_address_t addr = regstart + IMAGE_OFFSET + 0x200000;

    mach_hdr_t hdr;
    DEBUG("Looking for mach header at " ADDR "...", addr);
    if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
    {
        DEBUG("Kernel I/O error, returning 0.");
        return 0;
    }
    if(hdr.magic == MACH_HEADER_MAGIC && hdr.filetype == MH_EXECUTE)
    {
        DEBUG("Success!");
    }
    else
    {
        DEBUG("Not a Mach-O header there, subtracting 0x200000.");
        addr -= 0x200000;
    }
    return addr;
}

typedef struct
{
    vm_address_t regstart;
    vm_address_t regend;
} get_kernel_base_cb_args_t;

static bool get_kernel_base_cb(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_cb_args_t *args = arg;
    DEBUG("Found region " ADDR "-" ADDR " with %c%c%c", addr, addr + size, (info->protection) & VM_PROT_READ ? 'r' : '-', (info->protection) & VM_PROT_WRITE ? 'w' : '-', (info->protection) & VM_PROT_EXECUTE ? 'x' : '-');
    if
    (
        (info->protection & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) == 0 &&
        size >          1024*1024*1024 &&
#ifdef __LP64__
        size <= 16ULL * 1024*1024*1024 && // this is always true for 32-bit
#endif
        info->share_mode == SM_EMPTY
    )
    {
        if(args->regstart == 0 && args->regend == 0)
        {
            DEBUG("Found a matching memory region.");
            args->regstart = addr;
            args->regend   = addr + size;
        }
        else
        {
            DEBUG("Found more than one matching memory region, aborting.");
            return false;
        }
    }

    return true;
}

vm_address_t get_kernel_base(void)
{
    static vm_address_t kbase = 0;
    static bool initialized = false;
    if(!initialized)
    {
        DEBUG("Getting kernel base address...");

        DEBUG("Getting base region address...");
        get_kernel_base_cb_args_t args =
        {
            .regstart = 0,
            .regend = 0,
        };
        if(!foreach_kernel_region(&get_kernel_base_cb, &args))
        {
            return 0;
        }
        if(args.regstart == 0)
        {
            DEBUG("Failed to find base region, returning 0.");
            return 0;
        }
        if(args.regend < args.regstart)
        {
            DEBUG("Base region has overflowing size, returning 0.");
            return 0;
        }
        DEBUG("Base region is at " ADDR "-" ADDR ".", args.regstart, args.regend);

        vm_address_t addr = kCFCoreFoundationVersionNumber <= HAVE_TAGGED_REGIONS ? get_kernel_base_ios8(args.regstart) : get_kernel_base_ios9(args.regstart, args.regend);
        if(addr == 0)
        {
            return 0;
        }

        DEBUG("Got address " ADDR ", doing sanity checks...", addr);
        mach_hdr_t hdr;
        if(kernel_read(addr, sizeof(hdr), &hdr) != sizeof(hdr))
        {
            DEBUG("Kernel I/O error, returning 0.");
            return 0;
        }
        if(hdr.magic != MACH_HEADER_MAGIC)
        {
            DEBUG("Header has wrong magic, returning 0 (%08x)", hdr.magic);
            return 0;
        }
        if(hdr.filetype != MH_EXECUTE)
        {
            DEBUG("Header has wrong filetype, returning 0 (%u)", hdr.filetype);
            return 0;
        }
        if(hdr.cputype != MACH_TYPE)
        {
            DEBUG("Header has wrong architecture, returning 0 (%u)", hdr.cputype);
            return 0;
        }
        void *cmds = malloc(hdr.sizeofcmds);
        if(cmds == NULL)
        {
            DEBUG("Memory allocation error, returning 0.");
            return 0;
        }
        if(kernel_read(addr + sizeof(hdr), hdr.sizeofcmds, cmds) != hdr.sizeofcmds)
        {
            DEBUG("Kernel I/O error, returning 0.");
            free(cmds);
            return 0;
        }
        bool has_userland_address = false,
             has_linking = false,
             has_unixthread = false,
             has_exec = false;
        for
        (
            struct load_command *cmd = cmds, *end = (struct load_command*)((char*)cmds + hdr.sizeofcmds);
            cmd < end;
            cmd = (struct load_command*)((char*)cmd + cmd->cmdsize)
        )
        {
            switch(cmd->cmd)
            {
                case MACH_LC_SEGMENT:
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->vmaddr < KERNEL_SPACE)
                        {
                            has_userland_address = true;
                            goto end;
                        }
                        if(seg->initprot & VM_PROT_EXECUTE)
                        {
                            has_exec = true;
                        }
                        break;
                    }
                case LC_UNIXTHREAD:
                    has_unixthread = true;
                    break;
                case LC_LOAD_DYLIB:
                case LC_ID_DYLIB:
                case LC_LOAD_DYLINKER:
                case LC_ID_DYLINKER:
                case LC_PREBOUND_DYLIB:
                case LC_LOAD_WEAK_DYLIB:
                case LC_REEXPORT_DYLIB:
                case LC_LAZY_LOAD_DYLIB:
                case LC_DYLD_INFO:
                case LC_DYLD_INFO_ONLY:
                case LC_DYLD_ENVIRONMENT:
                case LC_MAIN:
                    has_linking = true;
                    goto end;
            }
        }
        end:;
        free(cmds);
        if(has_userland_address)
        {
            DEBUG("Found segment with userland address, returning 0.");
            return 0;
        }
        if(has_linking)
        {
            DEBUG("Found linking-related load command, returning 0.");
            return 0;
        }
        if(!has_unixthread)
        {
            DEBUG("Binary is missing LC_UNIXTHREAD, returning 0.");
            return 0;
        }
        if(!has_exec)
        {
            DEBUG("Binary has no executable segment, returning 0.");
            return 0;
        }

        DEBUG("Confirmed base address " ADDR ", caching it.", addr);
        kbase = addr;
        initialized = true;
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
    vm_size_t remainder = size,
              bytes_written = 0;

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
