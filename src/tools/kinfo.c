/*
 * kinfo.c - Print various kernel info
 *
 * Copyright (c) 2017 Siguza
 */

#include <stdbool.h>            // true
#include <stdio.h>              // printf, fprintf, stderr
#include <string.h>             // strcmp

#include <mach/vm_types.h>      // vm_address_t
#include <mach/thread_status.h> // arm_unified_thread_state_t

#include "arch.h"               // ADDR
#include "debug.h"              // slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO
#include "mach-o.h"             // CMD_ITERATE

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage: %s [-h] [-v [-d]]\n"
                    "    -b  Print the kernel text base\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -l  Print the kernel load commands (kernel header)\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

typedef struct
{
    uint32_t c :  8;
    uint32_t b :  8;
    uint32_t a : 16;
} version32_t;

typedef struct
{
    uint64_t e : 10;
    uint64_t d : 10;
    uint64_t c : 10;
    uint64_t b : 10;
    uint64_t a : 24;
} version64_t;

typedef struct
{
    uint64_t e : 48;
    uint64_t d : 16;
    uint64_t c : 16;
    uint64_t b : 16;
    uint64_t a : 32;
} my_uuid_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
#ifdef TARGET_MACOS
    x86_thread_state_t state;
#else
    arm_unified_thread_state_t state;
#endif
} thread_cmd_t;

int main(int argc, const char **argv)
{
    bool base = false,
         header = false;

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
        else if(strcmp(argv[i], "-b") == 0)
        {
            base = true;
        }
        else if(strcmp(argv[i], "-l") == 0)
        {
            header = true;
        }
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    size_t sum = base + header;
    if(sum != 1)
    {
        if(sum != 0)
        {
            fprintf(stderr, "[!] More than one action given\n\n");
        }
        print_usage(argv[0]);
        return sum == 0 ? 0 : -1;
    }

    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);
    if(base)
    {
        printf(ADDR "\n", kbase);
    }
    else if(header)
    {
        mach_hdr_t hdr_buf;
        if(kernel_read(kbase, sizeof(hdr_buf), &hdr_buf) != sizeof(hdr_buf))
        {
            fprintf(stderr, "[!] Kernel I/O error\n");
            return -1;
        }
        size_t hdr_size = sizeof(hdr_buf) + hdr_buf.sizeofcmds;

        mach_hdr_t *hdr = malloc(hdr_size);
        if(hdr == NULL)
        {
            fprintf(stderr, "[!] Failed to allocate header buffer: %s\n", strerror(errno));
            return -1;
        }
        if(kernel_read(kbase, hdr_size, hdr) != hdr_size)
        {
            fprintf(stderr, "[!] Kernel I/O error\n");
            return -1;
        }

        CMD_ITERATE(hdr, cmd)
        {
            switch(cmd->cmd)
            {
                case MACH_LC_SEGMENT:
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        printf(MACH_LC_SEGMENT_NAME ":  Mem: " ADDR "-" ADDR "  File: " ADDR "-" ADDR "  %c%c%c/%c%c%c  %s\n"
                              , (vm_address_t)seg->vmaddr, (vm_address_t)(seg->vmaddr + seg->vmsize), (vm_address_t)seg->fileoff, (vm_address_t)(seg->fileoff + seg->filesize)
                              , (seg->initprot & VM_PROT_READ) ? 'r' : '-', (seg->initprot & VM_PROT_WRITE) ? 'w' : '-', (seg->initprot & VM_PROT_EXECUTE) ? 'x' : '-'
                              , (seg->maxprot  & VM_PROT_READ) ? 'r' : '-', (seg->maxprot  & VM_PROT_WRITE) ? 'w' : '-', (seg->maxprot  & VM_PROT_EXECUTE) ? 'x' : '-'
                              , seg->segname);
                        mach_sec_t *sec = (mach_sec_t*)(seg + 1);
                        for(size_t i = 0; i < seg->nsects; ++i)
                        {
                            if(sec[i].flags == S_ZEROFILL)
                            {
                                printf("        Mem: " ADDR "-" ADDR "  File: %-*s  %s.%s\n"
                                       , (vm_address_t)sec[i].addr, (vm_address_t)(sec[i].addr + sec[i].size), (int)(4 * sizeof(void*) + 1), "Not mapped to file"
                                       , sec[i].segname, sec[i].sectname);
                            }
                            else
                            {
                                printf("        Mem: " ADDR "-" ADDR "  File: " ADDR "-" ADDR "  %s.%s\n"
                                       , (vm_address_t)sec[i].addr, (vm_address_t)(sec[i].addr + sec[i].size), (vm_address_t)sec[i].offset, (vm_address_t)(sec[i].offset + sec[i].size)
                                       , sec[i].segname, sec[i].sectname);
                            }
                        }
                    }
                    break;
                case LC_SYMTAB:
                    {
                        struct symtab_command *stab = (struct symtab_command*)cmd;
                        printf("LC_SYMTAB:\n"
                               "        Symbol table:           Offset 0x%x, %u entries\n"
                               "        String table:           Offset 0x%x, %u bytes\n"
                               , stab->symoff, stab->nsyms, stab->stroff, stab->strsize);
                    }
                    break;
                case LC_DYSYMTAB:
                    {
                        struct dysymtab_command *dstab = (struct dysymtab_command*)cmd;
                        printf("LC_DYSYMTAB:\n"
                               "        Local symbols:          Offset 0x%x, %u entries\n"
                               "        External symbols:       Offset 0x%x, %u entries\n"
                               "        Undefined symbols:      Offset 0x%x, %u entries\n"
                               "        Table of contents:      Offset 0x%x, %u entries\n"
                               "        Module table:           Offset 0x%x, %u entries\n"
                               "        Referenced symbols:     Offset 0x%x, %u entries\n"
                               "        Indirect symbols:       Offset 0x%x, %u entries\n"
                               "        External reloc entries: Offset 0x%x, %u entries\n"
                               "        Local reloc entries:    Offset 0x%x, %u entries\n"
                               , dstab->ilocalsym, dstab->nlocalsym, dstab->iextdefsym, dstab->nextdefsym, dstab->iundefsym, dstab->nundefsym
                               , dstab->tocoff, dstab->ntoc, dstab->modtaboff, dstab->nmodtab, dstab->extrefsymoff, dstab->nextrefsyms
                               , dstab->indirectsymoff, dstab->nindirectsyms, dstab->extreloff, dstab->nextrel, dstab->locreloff, dstab->nlocrel);
                    }
                    break;
                case LC_UUID:
                    {
                        my_uuid_t *uuid = (my_uuid_t*)&((struct uuid_command*)cmd)->uuid;
                        printf("LC_UUID:                        UUID: %08llX-%04llX-%04llX-%04llX-%012llX\n"
                               , uuid->a, uuid->b, uuid->c, uuid->d, uuid->e);
                    }
                    break;
                case LC_VERSION_MIN_MACOSX:
                case LC_VERSION_MIN_IPHONEOS:
                case LC_VERSION_MIN_TVOS:
                case LC_VERSION_MIN_WATCHOS:
                    {
                        struct version_min_command *vers = (struct version_min_command*)cmd;
                        version32_t *version = (version32_t*)&vers->version,
                                    *sdkvers = (version32_t*)&vers->sdk;
                        const char *str = cmd->cmd == LC_VERSION_MIN_MACOSX   ? "LC_VERSION_MIN_MACOSX" :
                                          cmd->cmd == LC_VERSION_MIN_IPHONEOS ? "LC_VERSION_MIN_IPHONEOS" :
                                          cmd->cmd == LC_VERSION_MIN_TVOS     ? "LC_VERSION_MIN_TVOS" : "LC_VERSION_MIN_WATCHOS";
                        printf("%s: %-*sMinimum version: %u.%u.%u, Built with SDK: %u.%u.%u\n"
                               , str, (int)(30 - strlen(str)), ""
                               , version->a, version->b, version->c
                               , sdkvers->a, sdkvers->b, sdkvers->c);
                    }
                    break;
                case LC_SOURCE_VERSION:
                    {
                        struct source_version_command *vers = (struct source_version_command*)cmd;
                        version64_t *version = (version64_t*)&vers->version;
                        printf("LC_SOURCE_VERSION:              Source version: %llu.%llu.%llu.%llu.%llu\n"
                               , version->a, version->b, version->c, version->d, version->e);
                    }
                    break;
                case LC_FUNCTION_STARTS:
                    {
                        struct linkedit_data_command *link = (struct linkedit_data_command*)cmd;
                        printf("LC_FUNCTION_STARTS:             Offset 0x%x, %u bytes\n"
                               , link->dataoff, link->datasize);
                    }
                    break;
                case LC_UNIXTHREAD:
                    {
                        thread_cmd_t *thread = (thread_cmd_t*)cmd;
#ifdef TARGET_MACOS
                        if(thread->state.tsh.flavor == x86_THREAD_STATE64)
                        {
                            x86_thread_state64_t *t = &thread->state.uts.ts64;
                            printf("LC_UNIXTHREAD:\n"
                                   "        rax: 0x%016llx rbx: 0x%016llx rcx: 0x%016llx rdx: 0x%016llx\n"
                                   "        rdi: 0x%016llx rsi: 0x%016llx rbp: 0x%016llx rsp: 0x%016llx\n"
                                   "         r8: 0x%016llx  r9: 0x%016llx r10: 0x%016llx r11: 0x%016llx\n"
                                   "        r12: 0x%016llx r13: 0x%016llx r14: 0x%016llx r15: 0x%016llx\n"
                                   "        rip: 0x%016llx rfl: 0x%016llx\n"
                                   "         cs: 0x%016llx  fs: 0x%016llx  gs: 0x%016llx\n"
                                   , t->__rax, t->__rbx, t->__rcx, t->__rdx
                                   , t->__rdi, t->__rsi, t->__rbp, t->__rsp
                                   , t->__r8 , t->__r9 , t->__r10, t->__r11
                                   , t->__r12, t->__r13, t->__r14, t->__r15
                                   , t->__rip, t->__rflags
                                   , t->__cs , t->__fs , t->__gs);
                        }
#else
                        if(thread->state.ash.flavor == ARM_THREAD_STATE)
                        {
                            arm_thread_state32_t *t = &thread->state.ts_32;
                            printf("LC_UNIXTHREAD:\n"
                                   "         r0: 0x%08x  r1: 0x%08x  r2: 0x%08x  r3: 0x%08x\n"
                                   "         r4: 0x%08x  r5: 0x%08x  r6: 0x%08x  r7: 0x%08x\n"
                                   "         r8: 0x%08x  r9: 0x%08x r10: 0x%08x r11: 0x%08x\n"
                                   "        r12: 0x%08x  sp: 0x%08x  lr: 0x%08x  pc: 0x%08x\n"
                                   "                                                       cpsr: 0x%08x\n"
                                   , t->__r[ 0], t->__r[ 1], t->__r[ 2], t->__r[ 3]
                                   , t->__r[ 4], t->__r[ 5], t->__r[ 6], t->__r[ 7]
                                   , t->__r[ 8], t->__r[ 9], t->__r[10], t->__r[11]
                                   , t->__r[12], t->__sp   , t->__lr   , t->__pc
                                   , t->__cpsr);
                        }
                        else if(thread->state.ash.flavor == ARM_THREAD_STATE64)
                        {
                            arm_thread_state64_t *t = &thread->state.ts_64;
                            printf("LC_UNIXTHREAD:\n"
                                   "         x0: 0x%016llx  x1: 0x%016llx  x2: 0x%016llx  x3: 0x%016llx\n"
                                   "         x4: 0x%016llx  x5: 0x%016llx  x6: 0x%016llx  x7: 0x%016llx\n"
                                   "         x8: 0x%016llx  x9: 0x%016llx x10: 0x%016llx x11: 0x%016llx\n"
                                   "        x12: 0x%016llx x13: 0x%016llx x14: 0x%016llx x15: 0x%016llx\n"
                                   "        x16: 0x%016llx x17: 0x%016llx x18: 0x%016llx x19: 0x%016llx\n"
                                   "        x20: 0x%016llx x21: 0x%016llx x22: 0x%016llx x23: 0x%016llx\n"
                                   "        x24: 0x%016llx x25: 0x%016llx x26: 0x%016llx x27: 0x%016llx\n"
                                   "        x28: 0x%016llx  fp: 0x%016llx  lr: 0x%016llx  sp: 0x%016llx\n"
                                   "         pc: 0x%016llx                                                        cpsr: 0x%08x\n"
                                   , t->__x[ 0], t->__x[ 1], t->__x[ 2], t->__x[ 3]
                                   , t->__x[ 4], t->__x[ 5], t->__x[ 6], t->__x[ 7]
                                   , t->__x[ 8], t->__x[ 9], t->__x[10], t->__x[11]
                                   , t->__x[12], t->__x[13], t->__x[14], t->__x[15]
                                   , t->__x[16], t->__x[17], t->__x[18], t->__x[19]
                                   , t->__x[20], t->__x[21], t->__x[22], t->__x[23]
                                   , t->__x[24], t->__x[25], t->__x[26], t->__x[27]
                                   , t->__x[28], t->__fp   , t->__lr   , t->__sp
                                   , t->__pc   , t->__cpsr);
                        }
#endif
                        else
                        {
                            printf("Cannot parse LC_UNIXTHREAD: Unknown flavor\n");
                        }
                    }
                    break;
                default:
                    printf("Unknown load command: 0x%x\n", cmd->cmd);
                    break;
            }
        }

        free(hdr);
    }

    return 0;
}
