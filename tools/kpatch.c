/*
 * kpatch.c - Apply patches to a running kenel
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 */

#include <stdio.h>              // printf
#include <string.h>             // memset, strlen

#include <mach/kern_return.h>   // KERN_SUCCESS, kern_return_t
#include <mach/vm_types.h>      // vm_address_t
#include <sys/sysctl.h>         // sysctlbyname

#include "arch.h"               // ADDR
#include "libkern.h"            // get_kernel_base, find_bytes_kern, write_kernel

int main(int argc, char** argv)
{
    char uuid[0x50];
    size_t size = 0x50;
    memset(uuid, 0, size);
    vm_address_t kbase, uuid_addr;
    kern_return_t ret;

    if(argc < 2)
    {
        printf("Usage: kpatch new-uuid\n");
        return -1;
    }
    if((ret = sysctlbyname("kern.uuid", uuid, &size, NULL, 0)) != KERN_SUCCESS)
    {
        printf("[!] failed to create uuid, sysctlbyname returned %i\n", ret);
        return -1;
    }
    printf("[*] uuid: %s\n", uuid);
    if((kbase = get_kernel_base()) == 0)
    {
        printf("[!] failed to get the kernel base address\n");
        return -1;
    }
    if((uuid_addr = find_bytes_kern(kbase, kbase + 0x1000000, (unsigned char*)uuid, strlen(uuid))) == 0)
    {
        printf("[!] failed to find the uuid in kernel memory\n");
        return -1;
    }
    printf("[*] found uuid at 0x" ADDR "\n", uuid_addr);
    write_kernel(uuid_addr, (unsigned char*)argv[1], strlen(argv[1]) + 1);
    printf("[*] done, check \"sysctl kern.uuid\"\n");

    return 0;
}
