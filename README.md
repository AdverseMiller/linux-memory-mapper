# linux-memory-mapper
A oneshot driver to remap the VMAs and PFNs of one process into another, effectively allowing for direct memory access from a different process.

The driver can be loaded with 2 parameters, target_pid and calling_pid. The target PID's memory will be remapped into the calling PID's address space.

Example:

  `insmod main.ko calling_pid=1000 target_pid=15000`

As of now, it does not seem possible to remap the stack of the target process. There might also be some other rare cases in which it a VMA cannot be remapped, not all configurations have been tested.
