/*
 * kdump.c - Dump the kernel
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <errno.h>              // errno
#include <stdio.h>              // FILE, fopen, fwrite, fclose, fprintf, stderr
#include <stdlib.h>             // free, malloc
#include <string.h>             // memcpy, memset, strerror

#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/mach_types.h>    // task_t
#include <mach/vm_types.h>      // vm_address_t
#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/mach_types.h>    // task_t
#include <mach/message.h>       // mach_msg_type_number_t
#include <mach/vm_inherit.h>    // VM_INHERIT_*
#include <mach/vm_map.h>        // vm_region_recurse_64
#include <mach/vm_prot.h>       // VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE
#include <mach/vm_region.h>     // VM_REGION_SUBMAP_INFO_COUNT_64, vm_region_info_t, vm_region_submap_info_data_64_t
#include <mach/vm_types.h>      // vm_address_t, vm_size_t


#include "arch.h"               // ADDR, mach_*
#include "debug.h"              // slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO, kernel_read
#include "mach-o.h"             // CMD_ITERATE

#define max(a, b) (a) > (b) ? (a) : (b)

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage: %s [-h] [-v [-d] [-b 0xKBASE]] [kernel.bin]\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    "    -b  Supply kbase already found using kinfo since it can be slow to find on macOS\n"
                    , self);
}

typedef struct kregion {
    uintptr_t addr;
    size_t size;
    uint32_t prot;
    uint32_t maxprot;
    uint32_t tag;
} kregion_t;

#define MAX_KCACHE_REGIONS 16
#define MAX_NON_KCACHE_REGIONS 4096

#define HEADER_VMADDR 0xd000000000000000

int is_in_regions(uintptr_t addr, const kregion_t *regions, int nregions) {
    for (int i = 0; i < nregions; ++i) {
        if (addr == regions[i].addr)
            return true;
    }
    return false;
}


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
        case VM_KERN_MEMORY_CPU:                return "CPU";
        case VM_KERN_MEMORY_PMAP:               return "PMAP";
        case VM_KERN_MEMORY_PTE:                return "PTE";
        case VM_KERN_MEMORY_ZONE:               return "Zalloc";
        case VM_KERN_MEMORY_KALLOC:             return "Kalloc";
        case VM_KERN_MEMORY_COMPRESSOR:         return "CMP";
        case VM_KERN_MEMORY_COMPRESSED_DATA:    return "CMPDAT";
        case VM_KERN_MEMORY_PHANTOM_CACHE:      return "PHTM";
        case VM_KERN_MEMORY_WAITQ:              return "WAITQ";
        case VM_KERN_MEMORY_DIAG:               return "DIAG";
        case VM_KERN_MEMORY_LOG:                return "LOG";
        case VM_KERN_MEMORY_FILE:               return "FILE";
        case VM_KERN_MEMORY_MBUF:               return "MBUF";
        case VM_KERN_MEMORY_UBC:                return "UBC";
        case VM_KERN_MEMORY_SECURITY:           return "SEC";
        case VM_KERN_MEMORY_MLOCK:              return "MLOCK";
        case VM_KERN_MEMORY_REASON:             return "REASON";
        case VM_KERN_MEMORY_SKYWALK:            return "Skywalk";
        case VM_KERN_MEMORY_LTABLE:             return "LTABLE";
    }

    return tag >= VM_KERN_MEMORY_FIRST_DYNAMIC ? "DYN" : "???";
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


kregion_t kcache_regions[MAX_KCACHE_REGIONS] = { { 0 } };
kregion_t non_kcache_regions[MAX_NON_KCACHE_REGIONS] = { { 0 } };
int num_kcache_regions = 0;
int num_non_kcache_regions = 0;
size_t non_kcache_size = 0;

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
        if (size < 1024*1024*1 && info.protection & VM_PROT_READ && !(info.user_tag & VM_KERN_MEMORY_STACK) && !(info.share_mode != SM_SHARED_ALIASED) && !is_in_regions(addr, kcache_regions, MAX_KCACHE_REGIONS)) {
            non_kcache_regions[num_non_kcache_regions].addr = addr;
            non_kcache_regions[num_non_kcache_regions].size = size;
            non_kcache_regions[num_non_kcache_regions].tag = info.user_tag;
            non_kcache_regions[num_non_kcache_regions].prot = info.protection;
            non_kcache_regions[num_non_kcache_regions].maxprot = info.max_protection;
            num_non_kcache_regions++;
            non_kcache_size += size;
        }

        if(info.is_submap)
        {
            print_range(kernel_task, extended, gaps, level + 1, addr, addr + size);
        }
    }
}


int main(int argc, const char **argv)
{
    vm_address_t kbase = 0;
    FILE* f;
    size_t filesize = 0;
    unsigned char *binary;
    mach_hdr_t hdr_buf;
    size_t hdr_size;
    mach_hdr_t *orig_hdr, *hdr;
    mach_seg_t *seg;
    const char *outfile = "kernel.bin";

    int aoff;
    for(aoff = 1; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-')
        {
            break;
        }
        if(strcmp(argv[aoff], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        if(strcmp(argv[aoff], "-d") == 0)
        {
            slow = true;
        }
        else if(strcmp(argv[aoff], "-v") == 0)
        {
            verbose = true;
        }
        else if(strcmp(argv[aoff], "-b") == 0)
        {
            kbase = strtoull(argv[aoff+1], NULL, 16);
            ++aoff;
        }
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[aoff]);
            print_usage(argv[0]);
            return -1;
        }
    }
    if(argc - aoff > 1)
    {
        fprintf(stderr, "[!] Too many arguments\n\n");
        print_usage(argv[0]);
        return -1;
    }
    else if(argc - aoff == 1)
    {
        outfile = argv[aoff];
    }

    if (!kbase) {
        KERNEL_BASE_OR_GTFO(kbase);
    }
    fprintf(stderr, "[*] Found kernel base at address 0x" ADDR "\n", kbase);

    if(kernel_read(kbase, sizeof(hdr_buf), &hdr_buf) != sizeof(hdr_buf))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    hdr_size = sizeof(hdr_buf) + hdr_buf.sizeofcmds;

    orig_hdr = malloc(hdr_size);
    if(orig_hdr == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "[*] Reading kernel header...\n");
    if(kernel_read(kbase, hdr_size, orig_hdr) != hdr_size)
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }

    /*
     * We now have the mach-o header with the LC_SEGMENT
     * load commands in it.
     * Next we are going to redo the loading process,
     * parse each load command and read the data from
     * vmaddr into fileoff.
     * Some parts of the mach-o can not be restored (e.g. LC_SYMTAB).
     * The load commands for these parts will be removed from the final
     * executable.
     */


    int ncmds = 0;

    size_t total_cmd_size = 0;
    uintptr_t base_fileoff = 0;
    uintptr_t total_vmsize = 0;
    // loop through all segments once to determine file size
    CMD_ITERATE(orig_hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                seg = (mach_seg_t*)cmd;
                if (!strcmp(seg->segname, "__LINKEDIT") ||
                    !strcmp(seg->segname, "__KLD")) {
                    break;
                }
                total_cmd_size += seg->cmdsize;
                total_vmsize += seg->vmsize;
                kcache_regions[num_kcache_regions].addr = seg->vmaddr;
                kcache_regions[num_kcache_regions].size = seg->vmsize;
                num_kcache_regions++;
                ncmds++;
                break;
            case LC_UUID:
            case LC_UNIXTHREAD:
            case LC_SOURCE_VERSION:
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS:
                total_cmd_size += cmd->cmdsize;
                ncmds++;
                break;
        }
    }

    task_t kernel_task;
    KERNEL_TASK_OR_GTFO(kernel_task);
    print_range(kernel_task, 0, 1, 1, 0, ~0);
    ncmds += num_non_kcache_regions;
    total_cmd_size += num_non_kcache_regions * (sizeof(mach_seg_t) + sizeof(mach_sec_t));

    // HEADER seg
    ncmds += 1;
    // total_cmd_size = sizeof(mach_seg_t) + sizeof(mach_sec_t);
    total_cmd_size += sizeof(mach_seg_t);

    size_t new_hdr_size = sizeof(*orig_hdr) + total_cmd_size;
    hdr = malloc(new_hdr_size);
    if(hdr == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer: %s\n", strerror(errno));
        return -1;
    }
    memset(hdr, 0, new_hdr_size);
    memcpy(hdr, orig_hdr, sizeof(*orig_hdr));
    hdr->ncmds = 0;
    hdr->sizeofcmds = 0;

    filesize = sizeof(*orig_hdr) + total_cmd_size + total_vmsize + non_kcache_size;
    // filesize = new_hdr_size + total_vmsize;
    fprintf(stderr, "[*] Output binary size: %p, first segment offset: %p\n", (void *)filesize, (void *)base_fileoff);
    binary = malloc(filesize);
    if(binary == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate dump buffer: %s\n", strerror(errno));
        return -1;
    }
    memset(binary, 0, filesize);

    mach_seg_t *hdr_seg = (mach_seg_t *)(hdr + 1);
    hdr_seg->cmd = MACH_LC_SEGMENT;
    // hdr_seg->cmdsize = sizeof(mach_seg_t) + sizeof(mach_sec_t);
    hdr_seg->cmdsize = sizeof(mach_seg_t);
    hdr_seg->fileoff = 0;
    hdr_seg->filesize = sizeof(*orig_hdr) + total_cmd_size;
    hdr_seg->vmaddr = HEADER_VMADDR;
    hdr_seg->vmsize = hdr_seg->filesize;
    hdr_seg->maxprot = VM_PROT_READ;
    hdr_seg->initprot = VM_PROT_READ;
    hdr_seg->nsects = 0;
    strcpy(hdr_seg->segname, "__HEADER");
    // mach_sec_t *hdr_sec = (mach_sec_t *)(hdr_seg + 1);
    // strcpy(hdr_sec->sectname, "__header");
    // strcpy(hdr_sec->segname, "__HEADER");
    // hdr_sec->addr = HEADER_VMADDR;
    // hdr_sec->size = hdr_seg->filesize;
    // hdr_sec->offset = 0;
    hdr->sizeofcmds += hdr_seg->cmdsize;
    hdr->ncmds++;

    uintptr_t total_written_vmsize = hdr_seg->filesize;

    // loop again to restore everything
    fprintf(stderr, "[*] Restoring segments...\n");
    CMD_ITERATE(orig_hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                seg = (mach_seg_t*)cmd;
                fprintf(stderr, "[+] Found segment %s\n", seg->segname);
                if (!strcmp(seg->segname, "__LINKEDIT") ||
                    !strcmp(seg->segname, "__KLD")) {
                    fprintf(stderr, "[*] Skipping %s\n", seg->segname);
                    break;
                }
                mach_seg_t *new_seg = memcpy((char*)(hdr + 1) + hdr->sizeofcmds, seg, seg->cmdsize);
                new_seg->fileoff = base_fileoff + total_written_vmsize;
                new_seg->filesize = seg->vmsize;
                if (strcmp(seg->segname, "__PRELINK_INFO")) {
                    fprintf(stderr, "\tReading %p from %p to offset %p\n", (void *)seg->vmsize, (void*)seg->vmaddr, (void *)new_seg->fileoff);
                    if(kernel_read(seg->vmaddr, seg->vmsize, binary + new_seg->fileoff) != seg->vmsize)
                    {
                        fprintf(stderr, "[!] Kernel I/O error\n");
                        return -1;
                    }
                } else {
                    // skipping __PRELINK_INFO makes IDA unhappy so just leave it in but zero and IDA
                    // will split the kernelcache via Mach-O magic searching
                    fprintf(stderr, "\tZero filling __PRELINK_INFO since the kernel has already freed it.\n");
                }
                uintptr_t sec_written_size = 0;
                mach_sec_t *new_sec = (mach_sec_t *)((char *)new_seg + sizeof(mach_seg_t));
                SEC_ITERATE(seg, sec)
                {
                    memcpy(new_sec, sec, sizeof(mach_sec_t));
                    uintptr_t sec_offset_in_seg = sec->addr - seg->vmaddr;
                    new_sec->offset = new_seg->fileoff + sec_offset_in_seg;
                    if ((new_sec->flags & SECTION_TYPE) == S_ZEROFILL) {
                        new_sec->flags = (new_sec->flags & SECTION_ATTRIBUTES) | S_REGULAR;
                    }
                    new_sec++;
                    sec_written_size += sec->size;
                }
                total_written_vmsize += seg->vmsize;
                hdr->sizeofcmds += cmd->cmdsize;
                hdr->ncmds++;
                break;
            case LC_UUID:
            case LC_UNIXTHREAD:
            case LC_SOURCE_VERSION:
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS:
                memcpy((char*)(hdr + 1) + hdr->sizeofcmds, cmd, cmd->cmdsize);
                hdr->sizeofcmds += cmd->cmdsize;
                hdr->ncmds++;
                break;
        }
    }

    for (int i = 0; i < num_non_kcache_regions; ++i) {
        kregion_t reg = non_kcache_regions[i];
        mach_seg_t *seg = (mach_seg_t *)((char *)(hdr + 1) + hdr->sizeofcmds);
        seg->cmd = MACH_LC_SEGMENT;
        seg->cmdsize = sizeof(mach_seg_t) + sizeof(mach_sec_t);
        seg->fileoff = total_written_vmsize;
        seg->filesize = reg.size;
        seg->vmaddr = reg.addr;
        seg->vmsize = reg.size;
        seg->maxprot = reg.maxprot;
        seg->initprot = reg.prot;
        seg->nsects = 1;
        snprintf(seg->segname, sizeof(seg->segname), "__NKC_%d", i);
        mach_sec_t *sec = (mach_sec_t *)(seg + 1);
        snprintf(sec->segname, sizeof(sec->segname), "__NKC_%d", i);
        snprintf(sec->sectname, sizeof(sec->sectname), "__nkc_%d", i);
        sec->addr = reg.addr;
        sec->size = reg.size;
        sec->offset = total_written_vmsize;
        if(kernel_read(reg.addr, reg.size, binary + seg->fileoff) != reg.size)
        {
            fprintf(stderr, "[!] Kernel I/O error\n");
            return -1;
        }
        hdr->sizeofcmds += seg->cmdsize;
        hdr->ncmds++;
        total_written_vmsize += seg->vmsize;
    }

    // now replace the old header with the new one ...
    memcpy(binary, hdr, sizeof(*hdr) + hdr->sizeofcmds);

    // ... and write the final binary to file
    f = fopen(outfile, "wb");
    if(f == NULL)
    {
        fprintf(stderr, "[!] Failed to open %s for writing: %s\n", outfile, strerror(errno));
        return -1;
    }
    fwrite(binary, filesize, 1, f);

    fprintf(stderr, "[*] Done, wrote %lu bytes to %s\n", filesize, outfile);
    fclose(f);

    free(binary);
    free(hdr);
    free(orig_hdr);

    return 0;
}
