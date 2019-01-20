# Using the KVM API

This project followed [this article](https://lwn.net/Articles/658511/) to create a VM from scratch using the KVM.

The VM executes a program that adds `2+2` and prints the output to the console. To do this, we need to open the `/dev/kvm` file,
create a vm, add a vcpu to that vm, initialize memory and registers and, run the vm. While running, the vm exits when it needs
device emulation. In our case, we emulate a device to output the `2+2` result and run a `printf` on the result to print it to
the console.

## Link

https://lwn.net/Articles/658511/
