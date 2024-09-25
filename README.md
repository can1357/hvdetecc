# hvdetecc

This project demonstrates various techniques for detecting the presence of a hypervisor or virtual machine monitor (VMM) on x86-64 systems. It explores common pitfalls in VMX (Intel Virtualization Technology) and SVM (AMD Secure Virtual Machine) based VM monitor implementations, as well as the underlying hardware implementation, and how they can be abused to detect the presence of the monitor.

## Key Features

1. **Processor Behavior Tests**: Examines various CPU features and behaviors that may be imperfectly emulated in a virtual environment.

2. **Performance Monitoring**: Utilizes performance monitoring counters (PMCs) to detect anomalies in instruction execution and timing.

3. **Memory Management Tests**: Checks for discrepancies in memory access patterns and TLB (Translation Lookaside Buffer) behavior.

4. **Timing Analysis**: Employs multiple timing sources (as well as equivalent side-channels like DRAM power utilization, or software clocks) to identify inconsistencies that may reveal virtualization overhead of VMEXITs.

5. **MSR (Model Specific Register) Tests**: Examines the behavior of various MSRs that may be handled differently in a virtualized environment.

6. **Interrupt Handling Tests**: Checks for anomalies in interrupt delivery and handling.

7. **Type 1 Hypervisor Detection**: Detects the presence of a Type 1 hypervisors by checking SMBIOS, ACPI, tables as well as PCI enumeration.
