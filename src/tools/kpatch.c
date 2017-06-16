/*
 * kpatch.c - Apply patches to a running kenel
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#include <errno.h>              // errno
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // free, malloc, strtoull
#include <string.h>             // strcmp

#include <mach/vm_types.h>      // vm_address_t, vm_size_t

#include "arch.h"               // SIZE
#include "debug.h"              // slow, verbose
#include "libkern.h"            // kernel_write

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s [options] -f addr file\n"
                    "    %s [options] -w/-q addr 0x...\n"
                    "    %s [options] -x addr ...\n"
                    "\n"
                    "Options:\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -f  Read patch from file\n"
                    "    -h  Print this help\n"
                    "    -q  Patch uint64 from immediate\n"
                    "        (Requires addr to be 8-byte aligned)\n"
                    "    -v  Verbose (debug output)\n"
                    "    -w  Patch uint32 from immediate\n"
                    "        (Requires addr to be 4-byte aligned)\n"
                    "    -x  Patch from immediate hex string\n"
                    "        (little endian, must have even amount of chars)\n"
                    , self, self, self);
}

int main(int argc, const char **argv)
{
    char *end;
    bool file = false,
         wide = false,
         quad = false,
         hex = false;

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
        else if(strcmp(argv[aoff], "-f") == 0)
        {
            file = true;
        }
        else if(strcmp(argv[aoff], "-w") == 0)
        {
            wide = true;
        }
        else if(strcmp(argv[aoff], "-q") == 0)
        {
            quad = true;
        }
        else if(strcmp(argv[aoff], "-x") == 0)
        {
            hex = true;
        }
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[aoff]);
            print_usage(argv[0]);
            return -1;
        }
    }

    size_t sum = file + wide + quad + hex;
    if(sum != 1)
    {
        if(sum != 0)
        {
            fprintf(stderr, "[!] More than one action given.\n\n");
        }
        print_usage(argv[0]);
        return sum == 0 ? 0 : -1;
    }

    if(argc - aoff != 2)
    {
        fprintf(stderr, "[!] Too %s arguments.\n\n", (argc - aoff) < 2 ? "few" : "many");
        print_usage(argv[0]);
        return -1;
    }

    errno = 0;
    vm_address_t addr = strtoull(argv[argc - 2], &end, 0);
    if(argv[argc - 2][0] == '\0' || end[0] != '\0' || errno != 0)
    {
        fprintf(stderr, "[!] Failed to parse \"%s\": %s\n", argv[argc - 2], argv[argc - 2][0] == '\0' ? "zero characters given" : strerror(errno));
        return -1;
    }

    // before we do any memory allocation
    KERNEL_TASK_OR_GTFO();

    uint64_t imm;
    void *patch = NULL;
    vm_size_t len = 0;
    if(file)
    {
        //FILE *f = fopen();
    }
    else if(hex)
    {

    }
    else if(wide || quad)
    {
        errno = 0;
        imm = strtoull(argv[argc - 1], &end, 0);
        if(argv[argc - 1][0] == '\0' || end[0] != '\0' || errno != 0)
        {
            fprintf(stderr, "[!] Failed to parse \"%s\": %s\n", argv[argc - 1], argv[argc - 1][0] == '\0' ? "zero characters given" : strerror(errno));
            return -1;
        }

        patch = &imm;
        len = quad ? sizeof(uint64_t) : sizeof(uint32_t);

        if(addr % len != 0)
        {
            fprintf(stderr, "[!] Address is not " SIZE "-byte aligned\n", len);
            return -1;
        }
    }

    if(patch == NULL || len == 0)
    {
        fprintf(stderr, "[!] Failed to parse patch\n");
        return -1;
    }

    vm_size_t written = kernel_write(addr, len, patch);
    if(written != len)
    {
        fprintf(stderr, "[!] Error, wrote " SIZE " bytes instead of " SIZE "\n", written, len);
        return -1;
    }

    fprintf(stderr, "[*] Done\n");
    return 0;
}
