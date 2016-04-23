/*
 * kdump.c - Kernel dumper code
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach_init.h>
#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include <libkern.h>
#include <mach-o/binary.h>

#define MAX_HEADER_SIZE 0x2000

#define max(a, b) (a) > (b) ? (a) : (b)

#if __LP64__
typedef struct mach_header_64 mach_hdr_t;
typedef struct segment_command_64 mach_seg_t;
#else
typedef struct mach_header mach_hdr_t;
typedef struct segment_command mach_seg_t;
#endif

int main()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_address_t kbase;
    FILE* f;
    size_t filesize = 0;
    unsigned char *buf,     // will hold the original mach-o header and load commands
                  *header,  // header for the new mach-o file
                  *binary;  // mach-o will be reconstructed in here
    mach_hdr_t *orig_hdr, *hdr;
    mach_seg_t *seg;

    buf = malloc(MAX_HEADER_SIZE);
    header = malloc(MAX_HEADER_SIZE);
    if(buf == NULL || header == NULL)
    {
        printf("[!] Failed to allocate header buffer\n");
        return -1;
    }
    memset(header, 0, MAX_HEADER_SIZE);
    orig_hdr = (mach_hdr_t*)buf;
    hdr = (mach_hdr_t*)header;

    ret = get_kernel_task(&kernel_task);
    if(ret != KERN_SUCCESS)
    {
        printf("[!] Failed to get kernel task\n");
        return -1;
    }

    if((kbase = get_kernel_base()) == 0)
    {
        printf("[!] Failed to locate kernel\n");
        return -1;
    }
    printf("[*] Found kernel base at address 0x" ADDR "\n", kbase);

    printf("[*] Reading kernel header...\n");
    read_kernel(kbase, MAX_HEADER_SIZE, buf);
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
            case LC_SEGMENT:
            case LC_SEGMENT_64:
                seg = (mach_seg_t*)cmd;
                filesize = max(filesize, seg->fileoff + seg->filesize);
                break;
        }
    }
    binary = malloc(filesize);
    if(binary == NULL)
    {
        printf("[!] Failed to allocate dump buffer\n");
        return -1;
    }
    memset(binary, 0, filesize);

    // loop again to restore everything
    printf("[*] Restoring segments...\n");
    CMD_ITERATE(orig_hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case LC_SEGMENT:
            case LC_SEGMENT_64:
                seg = (mach_seg_t*)cmd;
                printf("[+] Found segment %s\n", seg->segname);
                read_kernel(seg->vmaddr, seg->filesize, binary + seg->fileoff);
            case LC_UUID:
            case LC_UNIXTHREAD:
            case 0x25:
            case 0x2a:
            case 0x26:
                memcpy(header + sizeof(*hdr) + hdr->sizeofcmds, cmd, cmd->cmdsize);
                hdr->sizeofcmds += cmd->cmdsize;
                hdr->ncmds++;
                break;
        }
    }

    // now replace the old header with the new one ...
    memcpy(binary, header, sizeof(*hdr) + orig_hdr->sizeofcmds);

    // ... and write the final binary to file
    f = fopen("kernel.bin", "wb");
    if(f == NULL)
    {
        printf("[!] Failed to open kdump.bin for writing\n");
        return -1;
    }
    fwrite(binary, filesize, 1, f);

    printf("[*] Done, wrote 0x%lx bytes\n", filesize);
    fclose(f);
    free(binary);
    free(buf);
    return 0;
}
