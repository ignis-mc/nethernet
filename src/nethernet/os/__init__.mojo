"""Operating-system services: clock, randomness, sockets and readiness.

This is the only package that performs I/O primitives. It supports Linux on
x86-64 and aarch64 and talks to the kernel directly through
`nethernet.os._sys.linux`; there is no libc dependency.
"""
