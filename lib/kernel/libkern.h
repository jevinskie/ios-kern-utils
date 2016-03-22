/*
 * kern.h - Libkern library.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 */

#ifndef LIBKERN_H
#define LIBKERN_H

#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/vm_types.h>

#include "arch.h"

/*
 * Functions to interact with the kernel address space.
 *
 * If not otherwise stated the following functions are 'unsafe', meaning
 * they are likely to panic the device if given invalid kernel addresses.
 *
 * You have been warned.
 */

/*
 * Get the kernel task port.
 *
 * This function should be safe at least on iOS 8 and earlier.
 */

kern_return_t get_kernel_task(task_t*);

/*
 * Return the base address of the running kernel.
 *
 * This function should be safe at least on iOS 8 and earlier.
 */
vm_address_t get_kernel_base();

/*
 * Read data from the kernel address space.
 *
 * Returns the number of bytes read.
 */
vm_size_t read_kernel(vm_address_t, vm_size_t, unsigned char*);

/*
 * Write data into the kernel address space.
 *
 * Returns the number of bytes written.
 */
vm_size_t write_kernel(vm_address_t, unsigned char*, vm_size_t);

/*
 * Find the given byte sequence in the kernel address space between start and end.
 *
 * Returns the address of the first occurance of bytes if found, otherwise 0.
 */
vm_address_t find_bytes_kern(vm_address_t, vm_address_t, unsigned char*, size_t);


#endif
