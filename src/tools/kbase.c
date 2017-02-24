/*
 * kbase.c - Print kernel base
 *
 * Copyright (c) 2017 Siguza
 */

#include <stdbool.h>            // true
#include <stdio.h>              // printf, fprintf, stderr
#include <string.h>             // strcmp

#include <mach/vm_types.h>      // vm_address_t

#include "arch.h"               // ADDR
#include "debug.h"              // slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO

static void print_usage(const char *self)
{
    fprintf(stderr, "Usage: %s [-h] [-v [-d]]\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

int main(int argc, const char **argv)
{
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
        else
        {
            fprintf(stderr, "[!] Unrecognized option: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);
    printf(ADDR "\n", kbase);

    return 0;
}
