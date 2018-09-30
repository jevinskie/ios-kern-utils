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

#define DB_HALT     0x1
#define DB_PRT      0x2
#define DB_NMI      0x4
#define DB_KPRT     0x8
#define DB_KDB      0x10
#define DB_SLOG     0x20
#define DB_ARP          0x40
#define DB_KDP_BP_DIS   0x80
#define DB_LOG_PI_SCRN  0x100
#define DB_KDP_GETC_ENA 0x200

#define DB_KERN_DUMP_ON_PANIC       0x400 /* Trigger core dump on panic*/
#define DB_KERN_DUMP_ON_NMI     0x800 /* Trigger core dump on NMI */
#define DB_DBG_POST_CORE        0x1000 /*Wait in debugger after NMI core */
#define DB_PANICLOG_DUMP        0x2000 /* Send paniclog on panic,not core*/
#define DB_REBOOT_POST_CORE     0x4000 /* Attempt to reboot after
                        * post-panic crashdump/paniclog
                        * dump.
                        */
#define DB_NMI_BTN_ENA      0x8000  /* Enable button to directly trigger NMI */
#define DB_PRT_KDEBUG       0x10000 /* kprintf KDEBUG traces */
#define DB_DISABLE_LOCAL_CORE   0x20000 /* ignore local core dump support */


static void print_usage(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s\n"
                    "\n"
                    "Options:\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    , self);
}

int main(int argc, const char **argv)
{
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

    // before we do any memory allocation
    KERNEL_TASK_OR_GTFO();
    vm_address_t kbase = 0;
    KERNEL_BASE_OR_GTFO(kbase);

    fprintf(stderr, "[*] kbase: %p\n", (void *)kbase);

    uint32_t cons_ops_index_off = 0x51ffe4;
    vm_address_t cons_ops_index_addr = kbase + cons_ops_index_off;
    uint32_t cons_ops_index;
    if(kernel_read(cons_ops_index_addr, sizeof(cons_ops_index), &cons_ops_index) != sizeof(cons_ops_index))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] cons_ops_index at %p is 0x%08x\n", (void *)cons_ops_index_addr, cons_ops_index);

    uint32_t disableConsoleOutput_off = 0x59038c;
    vm_address_t disableConsoleOutput_addr = kbase + disableConsoleOutput_off;
    uint32_t disableConsoleOutput;
    if(kernel_read(disableConsoleOutput_addr, sizeof(disableConsoleOutput), &disableConsoleOutput) != sizeof(disableConsoleOutput))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] disableConsoleOutput at %p is 0x%08x\n", (void *)disableConsoleOutput_addr, disableConsoleOutput);

    uint32_t enable_serial_output_off = 0x58f246;
    vm_address_t enable_serial_output_addr = kbase + enable_serial_output_off;
    uint8_t enable_serial_output;
    if(kernel_read(enable_serial_output_addr, sizeof(enable_serial_output), &enable_serial_output) != sizeof(enable_serial_output))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] enable_serial_output at %p is 0x%02hhx\n", (void *)enable_serial_output_addr, enable_serial_output);

    uint32_t debug_enable_off = 0x4aa7f4;
    vm_address_t debug_enable_addr = kbase + debug_enable_off;
    uint32_t debug_enable;
    if(kernel_read(debug_enable_addr, sizeof(debug_enable), &debug_enable) != sizeof(debug_enable))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] debug_enable at %p is 0x%08x\n", (void *)debug_enable_addr, debug_enable);



    cons_ops_index = 0;
    if(kernel_write(cons_ops_index_addr, sizeof(cons_ops_index), &cons_ops_index) != sizeof(cons_ops_index))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    if(kernel_read(cons_ops_index_addr, sizeof(cons_ops_index), &cons_ops_index) != sizeof(cons_ops_index))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] cons_ops_index at %p is 0x%08x\n", (void *)cons_ops_index_addr, cons_ops_index);

    disableConsoleOutput = 0;
    if(kernel_write(disableConsoleOutput_addr, sizeof(disableConsoleOutput), &disableConsoleOutput) != sizeof(disableConsoleOutput))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    if(kernel_read(disableConsoleOutput_addr, sizeof(disableConsoleOutput), &disableConsoleOutput) != sizeof(disableConsoleOutput))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] disableConsoleOutput at %p is 0x%08x\n", (void *)disableConsoleOutput_addr, disableConsoleOutput);

    enable_serial_output = 1;
    if(kernel_write(enable_serial_output_addr, sizeof(enable_serial_output), &enable_serial_output) != sizeof(enable_serial_output))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    if(kernel_read(enable_serial_output_addr, sizeof(enable_serial_output), &enable_serial_output) != sizeof(enable_serial_output))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] enable_serial_output at %p is 0x%02hhx\n", (void *)enable_serial_output_addr, enable_serial_output);

    if(kernel_set_prot(debug_enable_addr, sizeof(debug_enable), 1, VM_PROT_WRITE | VM_PROT_READ) != sizeof(debug_enable))
    {
        fprintf(stderr, "[!] Kernel I/O error set prot max\n");
        return -1;
    }

    if(kernel_set_prot(debug_enable_addr, sizeof(debug_enable), 0, VM_PROT_WRITE | VM_PROT_READ) != sizeof(debug_enable))
    {
        fprintf(stderr, "[!] Kernel I/O error set prot current\n");
        return -1;
    }

    debug_enable = DB_KPRT | DB_SLOG | DB_LOG_PI_SCRN | DB_PRT_KDEBUG;
    if(0 && kernel_write(debug_enable_addr, sizeof(debug_enable), &debug_enable) != sizeof(debug_enable))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    if(kernel_read(debug_enable_addr, sizeof(debug_enable), &debug_enable) != sizeof(debug_enable))
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }
    fprintf(stderr, "[*] debug_enable at %p is 0x%08x\n", (void *)debug_enable_addr, debug_enable);

    fprintf(stderr, "[*] Done\n");
    return 0;
}
