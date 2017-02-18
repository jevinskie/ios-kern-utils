/*
 * nvpatch.c - Patch kernel to unrestrict NVRAM variables
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Pupyshev Nikita
 * Copyright (c) 2017 Siguza
 *
 */

#include <errno.h>              // errno
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // free, malloc
#include <string.h>             // memmem, strcmp, strnlen

#include "arch.h"               // ADDR, MACH_*, mach_*
#include "debug.h"              // DEBUG, slow, verbose
#include "libkern.h"            // KERNEL_BASE_OR_GTFO, kernel_read
#include "mach-o.h"             // CMD_ITERATE

#define MAX_HEADER_SIZE 0x4000

#define STRING_SEG  "__TEXT"
#define STRING_SEC  "__cstring"
#define OFVAR_SEG   "__DATA"
#define OFVAR_SEC   "__data"

enum
{
    kOFVarTypeBoolean = 1,
    kOFVarTypeNumber,
    kOFVarTypeString,
    kOFVarTypeData,
};

enum
{
    kOFVarPermRootOnly = 0,
    kOFVarPermUserRead,
    kOFVarPermUserWrite,
    kOFVarPermKernelOnly,
};

typedef struct
{
    vm_address_t name;
    uint32_t type;
    uint32_t perm;
    int32_t offset;
} OFVar;

typedef struct
{
    vm_address_t addr;
    vm_size_t len;
    char *buf;
} segment_t;

#define MAX_TYPELEN 6
static const char* type_name(uint32_t type)
{
    switch(type)
    {
        case kOFVarTypeBoolean: return "bool";
        case kOFVarTypeNumber:  return "number";
        case kOFVarTypeString:  return "string";
        case kOFVarTypeData:    return "data";
    }
    return "???";
}

#define MAX_PERMLEN 5
static const char* perm_name(uint32_t perm)
{
    switch(perm)
    {
        case kOFVarPermUserWrite:   return "rw/rw";
        case kOFVarPermUserRead:    return "rw/r-";
        case kOFVarPermRootOnly:    return "rw/--";
        case kOFVarPermKernelOnly:  return "--/--";
    }
    return "???";
}

static void print_usage(const char *self)
{
    fprintf(stderr, "DISCLAIMER: YOU ARE MESSING WITH NVRAM AT YOUR OWN RISK!\n"
                    "\n"
                    "Usage:\n"
                    "    %s [options]\n"
                    "    %s [options] variable-name\n"
                    "\n"
                    "The first form lists all registered NVRAM variables with type and permission (as root/anyone).\n"
                    "The second form patches the kernel to unrestrict the given variable.\n"
                    "\n"
                    "Options:\n"
                    "    -d  Debug mode (sleep between function calls, gives\n"
                    "        sshd time to deliver output before kernel panic)\n"
                    "    -h  Print this help\n"
                    "    -v  Verbose (debug output)\n"
                    , self, self);
}

int main(int argc, const char **argv)
{
    const char *target = NULL;

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
        target = argv[aoff];
    }

    vm_address_t kbase;
    KERNEL_BASE_OR_GTFO(kbase);

    mach_hdr_t *hdr = malloc(MAX_HEADER_SIZE);
    if(hdr == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer (%s)\n", strerror(errno));
        return -1;
    }
    memset(hdr, 0, MAX_HEADER_SIZE);

    DEBUG("Reading kernel header... ");
    if(kernel_read(kbase, MAX_HEADER_SIZE, hdr) != MAX_HEADER_SIZE)
    {
        fprintf(stderr, "[!] Kernel I/O error\n");
        return -1;
    }

    segment_t
    cstring =
    {
        .addr = 0,
        .len = 0,
        .buf = NULL,
    },
    data =
    {
        .addr = 0,
        .len = 0,
        .buf = NULL,
    };
    CMD_ITERATE(hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                {
                    mach_seg_t *seg = (mach_seg_t*)cmd;
                    mach_sec_t *sec = (mach_sec_t*)(seg + 1);
                    for(size_t i = 0; i < seg->nsects; ++i)
                    {
                        if(strcmp(sec[i].segname, STRING_SEG) == 0 && strcmp(sec[i].sectname, STRING_SEC) == 0)
                        {
                            DEBUG("Found " STRING_SEG "." STRING_SEC " section at " ADDR, (vm_address_t)sec[i].addr);
                            cstring.addr = sec[i].addr;
                            cstring.len = sec[i].size;
                            cstring.buf = malloc(cstring.len);
                            if(cstring.buf == NULL)
                            {
                                fprintf(stderr, "[!] Failed to allocate section buffer (%s)\n", strerror(errno));
                                return -1;
                            }
                            if(kernel_read(cstring.addr, cstring.len, cstring.buf) != cstring.len)
                            {
                                fprintf(stderr, "[!] Kernel I/O error\n");
                                return -1;
                            }
                        }
                        else if(strcmp(sec[i].segname, OFVAR_SEG) == 0 && strcmp(sec[i].sectname, OFVAR_SEC) == 0)
                        {
                            DEBUG("Found " OFVAR_SEG "." OFVAR_SEC " section at " ADDR, (vm_address_t)sec[i].addr);
                            data.addr = sec[i].addr;
                            data.len = sec[i].size;
                            data.buf = malloc(data.len);
                            if(data.buf == NULL)
                            {
                                fprintf(stderr, "[!] Failed to allocate section buffer (%s)\n", strerror(errno));
                                return -1;
                            }
                            if(kernel_read(data.addr, data.len, data.buf) != data.len)
                            {
                                fprintf(stderr, "[!] Kernel I/O error\n");
                                return -1;
                            }
                        }
                    }
                }
                break;
        }
    }
    if(cstring.buf == NULL)
    {
        fprintf(stderr, "[!] Failed to find " STRING_SEG "." STRING_SEC " section\n");
        return -1;
    }
    if(data.buf == NULL)
    {
        fprintf(stderr, "[!] Failed to find " OFVAR_SEG "." OFVAR_SEC " section\n");
        return -1;
    }

    // This is the name of the first NVRAM variable
    char first[] = "little-endian?";
    char *str = memmem(cstring.buf, cstring.len, first, sizeof(first));
    if(str == NULL)
    {
        fprintf(stderr, "[!] Failed to find string \"%s\"\n", first);
        return -1;
    }
    vm_address_t str_addr = (str - cstring.buf) + cstring.addr;
    DEBUG("Found string \"%s\" at " ADDR, first, str_addr);

    // Now let's find a reference to it
    OFVar *gOFVars = NULL;
    for(vm_address_t *ptr = (vm_address_t*)data.buf, *end = (vm_address_t*)&data.buf[data.len]; ptr < end; ++ptr)
    {
        if(*ptr == str_addr)
        {
            gOFVars = (OFVar*)ptr;
            break;
        }
    }
    if(gOFVars == NULL)
    {
        fprintf(stderr, "[!] Failed to find gOFVariables\n");
        return -1;
    }
    vm_address_t gOFAddr = ((char*)gOFVars - data.buf) + data.addr;
    DEBUG("Found gOFVariables at " ADDR, gOFAddr);

    // Sanity checks
    size_t numvars = 0,
           longest_name = 0;
    for(OFVar *var = gOFVars; (char*)var < &data.buf[data.len]; ++var)
    {
        if(var->name == 0) // End marker
        {
            break;
        }
        if(var->name < cstring.addr || var->name >= cstring.addr + cstring.len)
        {
            fprintf(stderr, "[!] gOFVariables[%lu].name is out of bounds\n", numvars);
            return -1;
        }
        char *name = &cstring.buf[var->name - cstring.addr];
        size_t maxlen = cstring.len - (name - cstring.buf),
               namelen = strnlen(name, maxlen);
        if(namelen == maxlen)
        {
            fprintf(stderr, "[!] gOFVariables[%lu].name exceeds __cstring size\n", numvars);
            return -1;
        }
        for(size_t i = 0; i < namelen; ++i)
        {
            if(name[i] < 0x20 || name[i] >= 0x7f)
            {
                fprintf(stderr, "[!] gOFVariables[%lu].name contains non-printable character: 0x%02x\n", numvars, name[i]);
                return -1;
            }
        }
        longest_name = namelen > longest_name ? namelen : longest_name;
        switch(var->type)
        {
            case kOFVarTypeBoolean:
            case kOFVarTypeNumber:
            case kOFVarTypeString:
            case kOFVarTypeData:
                break;
            default:
                fprintf(stderr, "[!] gOFVariables[%lu] has unknown type: 0x%x\n", numvars, var->type);
                return -1;
        }
        switch(var->perm)
        {
            case kOFVarPermRootOnly:
            case kOFVarPermUserRead:
            case kOFVarPermUserWrite:
            case kOFVarPermKernelOnly:
                break;
            default:
                fprintf(stderr, "[!] gOFVariables[%lu] has unknown permissions: 0x%x\n", numvars, var->perm);
                return -1;
        }
        ++numvars;
    }
    if(numvars < 1)
    {
        fprintf(stderr, "[!] gOFVariables contains zero entries\n");
        return -1;
    }

    if(target == NULL) // Print list
    {
        DEBUG("gOFVariables:");

        for(size_t i = 0; i < numvars; ++i)
        {
            char *name = &cstring.buf[gOFVars[i].name - cstring.addr];
            printf("%-*s %-*s %-*s\n", (int)longest_name, name, MAX_TYPELEN, type_name(gOFVars[i].type), MAX_PERMLEN, perm_name(gOFVars[i].perm));
        }
    }
    else // Patch target
    {
        for(size_t i = 0; i < numvars; ++i)
        {
            char *name = &cstring.buf[gOFVars[i].name - cstring.addr];
            if(strcmp(name, target) == 0)
            {
                if(gOFVars[i].perm != kOFVarPermKernelOnly)
                {
                    fprintf(stderr, "[*] Variable \"%s\" is already writable for %s\n", target, gOFVars[i].perm == kOFVarPermUserWrite ? "everyone" : "root");
                    goto done;
                }
                vm_size_t off = ((char*)&gOFVars[i].perm) - data.buf;
                uint32_t newperm = kOFVarPermRootOnly;
                if(kernel_write(data.addr + off, sizeof(newperm), &newperm) != sizeof(newperm))
                {
                    fprintf(stderr, "[!] Kernel I/O error\n");
                    return -1;
                }
                fprintf(stderr, "[*] Successfully patched permissions for variable \"%s\"\n", target);
                goto done;
            }
        }
        fprintf(stderr, "[!] Failed to find variable \"%s\"\n", target);

        const char *assign = strchr(target, '=');
        if(assign != NULL)
        {
            size_t len = assign - target;
            fprintf(stderr, "[!] WARNING!\n"
                            "[!] Your variable name contains a '=' character, which is almost certainly wrong.\n"
                            "[!] If you meant to patch a variable and assign it a value, run the following:\n"
                            "\n"
                            "%s %.*s\n"
                            "nvram %s\n"
                            "\n"
                            , argv[0], (int)len, target, target);
        }
        return -1;

        done:;
    }

    free(cstring.buf);
    free(data.buf);
    free(hdr);

    return 0;
}
