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
    fprintf(stderr, "Usage: %s [-h] [-v [-d]] [kernel.bin]\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

int main(int argc, const char **argv)
{
    vm_address_t kbase;
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

    KERNEL_BASE_OR_GTFO(kbase);
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

    // loop through all segments once to determine file size
    CMD_ITERATE(orig_hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                seg = (mach_seg_t*)cmd;
                filesize = max(filesize, seg->fileoff + seg->filesize);
                break;
        }
    }
    binary = malloc(filesize);
    if(binary == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate dump buffer: %s\n", strerror(errno));
        return -1;
    }
    memset(binary, 0, filesize);

    // loop again to restore everything
    fprintf(stderr, "[*] Restoring segments...\n");
    CMD_ITERATE(orig_hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                seg = (mach_seg_t*)cmd;
                fprintf(stderr, "[+] Found segment %s\n", seg->segname);
                if(kernel_read(seg->vmaddr, seg->filesize, binary + seg->fileoff) != seg->filesize)
                {
                    fprintf(stderr, "[!] Kernel I/O error\n");
                    return -1;
                }
            case LC_UUID:
            case LC_UNIXTHREAD:
            case LC_SOURCE_VERSION:
            case LC_FUNCTION_STARTS:
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
    memcpy(binary, hdr, sizeof(*hdr) + orig_hdr->sizeofcmds);

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
