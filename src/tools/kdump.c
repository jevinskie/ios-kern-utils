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
    hdr = malloc(hdr_size);
    if(orig_hdr == NULL || hdr == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer: %s\n", strerror(errno));
        return -1;
    }
    memset(hdr, 0, hdr_size);

    fprintf(stderr, "[*] Reading kernel header...\n");
    if(kernel_read(kbase, hdr_size, orig_hdr) != hdr_size)
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    memcpy(hdr, orig_hdr, sizeof(*hdr));
    hdr->ncmds = 0;
    hdr->sizeofcmds = 0;

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
                    !strcmp(seg->segname, "__KLD") ||
                    !strcmp(seg->segname, "__PRELINK_INFO")) {
                    break;
                }
                total_vmsize += seg->vmsize;
                break;
        }
    }
    filesize = total_vmsize;
    fprintf(stderr, "[*] Output binary size: %p, first segment offset: %p\n", (void *)filesize, (void *)base_fileoff);
    binary = malloc(filesize);
    if(binary == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate dump buffer: %s\n", strerror(errno));
        return -1;
    }
    memset(binary, 0, filesize);

    uintptr_t total_written_vmsize = 0;

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
                    !strcmp(seg->segname, "__KLD") ||
                    !strcmp(seg->segname, "__PRELINK_INFO")) {
                    fprintf(stderr, "[*] Skipping %s\n", seg->segname);
                    break;
                }
                mach_seg_t *new_seg = memcpy((char*)(hdr + 1) + hdr->sizeofcmds, seg, seg->cmdsize);
                new_seg->fileoff = base_fileoff + total_written_vmsize;
                new_seg->filesize = seg->vmsize;
                fprintf(stderr, "     Reading %p from %p to offset %p\n", (void *)seg->vmsize, (void*)seg->vmaddr, (void *)new_seg->fileoff);
                if(kernel_read(seg->vmaddr, seg->vmsize, binary + new_seg->fileoff) != seg->vmsize)
                {
                    fprintf(stderr, "[!] Kernel I/O error\n");
                    return -1;
                }
                uintptr_t sec_written_size = 0;
                mach_sec_t *new_sec = (mach_sec_t *)((char *)new_seg + sizeof(mach_seg_t));
                SEC_ITERATE(seg, sec)
                {
                    memcpy(new_sec, sec, sizeof(mach_sec_t));
                    /*
                    uintptr_t sec_offset_in_seg = sec_written_size;
                    if (sec->offset) {
                        sec_offset_in_seg = sec->offset - seg->fileoff;
                    }
                    */
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

    // now replace the old header with the new one ...
    memset(binary, 0, base_fileoff);
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
