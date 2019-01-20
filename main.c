/*
 * Using the KVM API (https://lwn.net/Articles/658511/) with some modifications
 * and comments for my understanding.
 * Copyright (c) 2018 Nicolas Mesa
 *
 * Sample code for /dev/kvm API
 *
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

// Copied the includes from https://lwn.net/Articles/658512/
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

// Followed the instructions from https://lwn.net/Articles/658511/ with a few modifications and
// some comments.
int main(int argc, char *argv[]) {

	int kvm, ret, vmfd, vcpufd;
    uint8_t *mem;
    size_t mmap_size;
    struct kvm_run *run;
    struct kvm_sregs sregs;

    const uint8_t code[] = {
		0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
		0x00, 0xd8,       /* add %bl, %al */
		0x04, '0',        /* add $'0', %al */
		0xee,             /* out %al, (%dx) */
		0xb0, '\n',       /* mov $'\n', %al */
		0xee,             /* out %al, (%dx) */
		0xf4,             /* hlt */
    };

    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);

    if (kvm == -1)
        err(1, "Could not open kvm");

    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);

    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");

    // 12 is the stable version and will always be returned from now on. Anything different is unstable and
    // should not be used.
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);


    // Required to setup guest memory
    ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (ret == -1)
        err(1, "KVM_CHECK_EXTENSION");
    if (!ret)
        errx(1, "Expected the KVM_CAP_USER_MEMORY extension to be available");

    // Create a vm file descriptor
    vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long) 0);

    if (vmfd == -1)
        err(1, "KVM_CREATE_VM");


    // Allocate memory
    mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (!mem)
        err(1, "mmap");

    // Copy the code into memory and initialize the memory for the vm.
    memcpy(mem, code, sizeof(code));

    struct kvm_userspace_memory_region region = {
        // This number identifies each region that we pass to the KVM. If we were to pass the same value again, it would replace this one
        .slot = 0,
        // This is how the guest will see the physical address.
        .guest_phys_addr = 0x1000,
        // This is 1 page (or 0x1000 bytes)
        .memory_size = 0x1000,
        // Points to the actual memory location in this process.
        .userspace_addr = (uint64_t)mem,
    };

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");


    // Create a virtual CPU. The 0 is a sequntial CPU index
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);

    if (vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");


    // We want to get the kvm_run data structure. This represents the state of the CPU. The size of this varies
    // and we can't just use sizeof(*run) because the kernel usually uses a bit of extra memory for this. In
    // order to allocate the right amount of memory, we call to see how much memory we need to allocate.
    mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

    if (mmap_size < sizeof(*run))
        errx(1, "mmap_size (%ld) is smaller than kvm_run (%ld)", mmap_size, sizeof(*run));

    // Allocate the right amount of memory for the kvm_run data structure for vcpufd. Note that we pass in vcpufd to map that fd
    // to run.
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);

    if (!run)
        err(1, "mmap failed for kvm_run");

    // We need to modify a few special registers. To do this, without modifying everything, we first read the current
    // registers, make our change, and then write them again.
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);

    if (ret == -1)
        err(1, "KVM_GET_SREGS");

    sregs.cs.base = 0;
    sregs.cs.selector = 0;

    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);

    if (ret == -1)
        err(1, "KVM_SET_SREGS");


    // Now we set the regular registers. Most of them will have a value of 0.

    struct kvm_regs regs = {
        // Instruction pointer. We set it to 0x1000 which is where our code is. This address is relative to
        // cs (which we set to 0).
        .rip = 0x1000,
        // We add the two following registers.
        .rax = 2,
        .rbx = 2,
        // These flags are specified by the x86 architecture. This program will fail if they're not set.
        .rflags = 0x2,
    };


    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    // Here we keep calling KVM_RUN. This call runs the vcpu for the vcpufd passed and returns when the
    // virtualization stops for some reason. This reason can be that we need to emulate hardware. There,
    // we can go through the exit_reason mapped to that vcpu and handle / emulate accordingly.
    //
    // If we had more than on CPU, we would need to have multiple threads with the same loop but
    // with different vcpufds. That way, all of them would be running at the same time.
    while (1) {
        // Returns successfully when there's a need to emulate a device.
        ioctl(vcpufd, KVM_RUN, NULL);
        switch (run->exit_reason) {

        // When we get this instruction (the last one in our code above), we simply exit. I'm not sure
        // if there should be some cleanup involved or not.
        case KVM_EXIT_HLT:
            printf("Got a KVM_EXIT_HLT. Stopping now.\n");
            return 0;

        case KVM_EXIT_IO:
            if (run->io.direction == KVM_EXIT_IO_OUT &&
                    run->io.size == 1 &&
                    run->io.port == 0x3f8 && // we're emulating this port
                    run->io.count == 1)
                // The data to output is given by taking the base address of run and adding the data_offset (it's after
                // the run data structure finishes).
                putchar(*(((char *)run) + run->io.data_offset));
            else
                errx(1, "Unhandled KVM_EXIT_IO");
            break;

        // This error accurs when the vm is not properly setup (for instance if the eflags register is not set to 0x2).
        // Multiple errors could map to the same hardware_entry_failure_reason so careful reading of the documentation could be needed to
        // debug this. We add this to make debugging easier but it shouldn't be necessary for our VM if we don't
        // have any errors.
        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                    (unsigned long long)run->fail_entry.hardware_entry_failure_reason);


        // This kind of error occurs when the KVM has the actual error. For example, if the KVM doesn't know how to emaulate
        // an instruction.
        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
        }
    }

    return 0;
}
