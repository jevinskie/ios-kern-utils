/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Pupyshev Nikita
 * Copyright (c) 2017 Siguza
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>              // errno
#include <stdbool.h>            // bool, true, false
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, free
#include <string.h>             // memmem, strcmp, strerror

#include "arch.h"               // ADDR, mach_*
#include "debug.h"              // slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO, kernel_read, kernel_write

#define OFVARS_SEG_NAME "__DATA"
#define OFVARS_SECT_NAME "__data"
#define CSTRING_SEG_NAME "__TEXT"

#if __LP64__
#define IMAGE_DATA_ALIGNMENT 8
#else
#define IMAGE_DATA_ALIGNMENT 4
#endif

struct __attribute__((aligned(IMAGE_DATA_ALIGNMENT))) OFVariable {
    char   *variableName;
    uint32_t variableType;
    uint32_t variablePerm;
    int32_t variableOffset;
};
typedef struct OFVariable OFVariable;

bool validateOFVariables(OFVariable *ptr, unsigned int maxCount, vm_address_t cstringStart, vm_size_t cstringSize) {
    uint32_t currType = 1;
    int32_t currOfft = -1;

    uintptr_t variableName;
    uint32_t variableType;
    uint32_t variablePerm;
    int32_t variableOffset;
    for (unsigned int i = 0; i < maxCount; i++) {
        variableName = (uintptr_t)ptr->variableName;
        variableType = ptr->variableType;
        variablePerm = ptr->variablePerm;
        variableOffset = ptr->variableOffset;

        if (!variableName) {
            return i != 0;
        }
        if (variableName < cstringStart) {
            return false;
        }
        if (variableName >= (cstringStart + cstringSize)) {
            return false;
        }
        if (variableType > 4) {
            return false; //1-4
        }
        if (variablePerm > 3) {
            return false; //0-3
        }
        if (variableOffset <= currOfft) {
            if (variableOffset != -1) {
                return false;
            }
        } else {
            currOfft = variableOffset;
        }
        currType = variableType;
        ptr++;
    }
    return false;
}

void print_usage(const char *self)
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
            fprintf(stderr, "[!] Unrecognized option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);
    fprintf(stderr, "[*] Found kernel base at address 0x" ADDR "\n", kbase);

    mach_hdr_t header;
    if (kernel_read(kbase, sizeof(header), &header) != sizeof(header)) {
        fprintf(stderr, "[!] Kernel I/O failed\n");
        return -1;
    }

    if (header.magic != MACH_HEADER_MAGIC) {
        fprintf(stderr, "[!] Kernel Mach-O magic is invalid (%X)\n", header.magic);
        return -1;
    }

    uint32_t sizeofcmds = header.sizeofcmds;
    uint32_t ncmds = header.ncmds;

    void *lcBuf = malloc(sizeofcmds);
    if (!lcBuf) {
        fprintf(stderr, "[+] Memory allocation error (%s)\n", strerror(errno));
        return -1;
    }
    if (kernel_read(kbase + sizeof(header), sizeofcmds, lcBuf) != sizeofcmds) {
        fprintf(stderr, "[-] Kernel I/O failed\n");
        return -1;
    }

    vm_address_t ofvarsSectionAddress = 0;
    vm_size_t ofvarsSectionSize = 0;
    vm_address_t cstringSectionAddress = 0;
    vm_size_t cstringSectionSize = 0;

    mach_lc_t *lcPtr = lcBuf;
    mach_lc_t *lcEndPtr = lcBuf + sizeofcmds;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (lcPtr >= lcEndPtr) {
            fprintf(stderr, "[!] Invalid size of load commands\n");
            free(lcBuf);
            return -1;
        }

        if (lcPtr->cmd == MACH_LC_SEGMENT) {
            mach_seg_t *cmd = (mach_seg_t*)lcPtr;
            if (!strcmp(cmd->segname, OFVARS_SEG_NAME)) {
                uint32_t nsects = cmd->nsects;
                mach_sec_t *sec = (mach_sec_t*)&cmd[1];
                for (uint32_t j = 0; j < nsects; j++) {
                    if (!strcmp(sec->sectname, OFVARS_SECT_NAME)) {
                        ofvarsSectionAddress = sec->addr;
                        ofvarsSectionSize = sec->size;
                        fprintf(stderr, "[+] Found " OFVARS_SEG_NAME "." OFVARS_SECT_NAME " section at address " ADDR "\n", ofvarsSectionAddress);
                        break;
                    }
                    sec++;
                }
            } else if (!strcmp(cmd->segname, CSTRING_SEG_NAME)) {
                uint32_t nsects = cmd->nsects;
                mach_sec_t *sec = (mach_sec_t*)&cmd[1];
                for (uint32_t j = 0; j < nsects; j++) {
                    if (!strcmp(sec->sectname, "__cstring")) {
                        cstringSectionAddress = sec->addr;
                        cstringSectionSize = sec->size;
                        fprintf(stderr, "[+] Found " CSTRING_SEG_NAME ".__cstring section at address " ADDR "\n", cstringSectionAddress);
                        break;
                    }
                    sec++;
                }
            }
        }

        lcPtr = (struct load_command *)((uintptr_t)lcPtr + lcPtr->cmdsize);
    }
    free(lcBuf);

    if (!ofvarsSectionAddress) {
        fprintf(stderr, "[!] " OFVARS_SEG_NAME "." OFVARS_SECT_NAME " segment not found\n");
        return -1;
    } else if (!cstringSectionAddress) {
        fprintf(stderr, "[!] " CSTRING_SEG_NAME ".__cstring section not found\n");
        return -1;
    }

    fprintf(stderr, "[*] Dumping " OFVARS_SEG_NAME "." OFVARS_SECT_NAME " section...\n");
    void *ofvarsSectionBuf = malloc(ofvarsSectionSize);
    if (!ofvarsSectionBuf) {
        fprintf(stderr, "[!] Memory allocation error (%s)\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "[*] Dumping " CSTRING_SEG_NAME ".__cstring section...\n");
    void *cstringSectionBuf = malloc(cstringSectionSize);
    if (!cstringSectionBuf) {
        fprintf(stderr, "[!] Memory allocation error (%s)\n", strerror(errno));
        free(ofvarsSectionBuf);
        return -1;
    }

    if (kernel_read(ofvarsSectionAddress, ofvarsSectionSize, ofvarsSectionBuf) != ofvarsSectionSize) {
        fprintf(stderr, "[!] Kernel I/O failed\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }

    if (kernel_read(cstringSectionAddress, cstringSectionSize, cstringSectionBuf) != cstringSectionSize) {
        fprintf(stderr, "[!] Kernel I/O failed\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }

    void *aLittleEndian = memmem(cstringSectionBuf, cstringSectionSize, "little-endian?", 15);
    if (!aLittleEndian) {
        fprintf(stderr, "[!] \"little-endian?\" string not found\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }
    vm_address_t aLittleEndianAddress = aLittleEndian - cstringSectionBuf + cstringSectionAddress;

    void *ofvarsStart = memmem(ofvarsSectionBuf, ofvarsSectionSize, &aLittleEndianAddress, sizeof(aLittleEndianAddress));
    if (!ofvarsStart) {
        fprintf(stderr, "[!] Unable to find \"little-endian?\" string xref\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }
    vm_offset_t ofvarsAddress = ofvarsSectionAddress + (ofvarsStart - ofvarsSectionBuf);
    vm_size_t ofvarsMaxSize = ofvarsSectionAddress + ofvarsSectionSize - ofvarsAddress;

    if (!validateOFVariables(ofvarsStart, ofvarsMaxSize / sizeof(OFVariable), cstringSectionAddress, cstringSectionSize)) {
        fprintf(stderr, "[!] gOFVariables is corrupt\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }

    fprintf(stderr, "[+] Found valid gOFVariables at " ADDR "\n", ofvarsAddress);

    OFVariable *var = (OFVariable*)ofvarsStart;
    const char *name;
    while (var->variableName != NULL) {
        if (var->variablePerm == 3) {
            name = cstringSectionBuf + ((uintptr_t)var->variableName - cstringSectionAddress);
            var->variablePerm = 0;
            fprintf(stderr, "[*] Edited permissions for %s\n", name);
        }
        var++;
    }
    vm_size_t ofvarsSize = (void *)++var - ofvarsStart;

    fprintf(stderr, "[*] Applying kernel patch...\n");
    if (kernel_write(ofvarsAddress, ofvarsSize, ofvarsStart) != ofvarsSize) {
        fprintf(stderr, "[!] Kernel I/O failed\n");
        free(ofvarsSectionBuf);
        free(cstringSectionBuf);
        return -1;
    }

    fprintf(stderr, "[*] Done\n");

    free(ofvarsSectionBuf);
    free(cstringSectionBuf);

    return 0;
}
