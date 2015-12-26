# oyster
oyster is a runtime library for programming secure isolated regions (SIRs).
SIRs can be thought of as containers containing both code and data, which can not be accessed by any non-SIR code 
It provides strong security guaranteees (such as confidentiality) in the presence of an untrusted software stack.
The threat model considers all non-SIR code (the host application, operating system, hypervisor, SMM code, etc.) to be compromised or malicious. 
oyster provides the SIR developer with the following core primitives:
  * Communication: `send` and `recv` operations for arbitrary sized data on a secure channel. The secure channel is established with trusted remote parties using the Diffie-Hellman-Merkle protocol for symmetric key exchange.
  * Memory management: `malloc` and `free` operations for arbitrary sized regions
  * File System: `read` and `write` operations with confidentiality, integrity, and rollback-protection. It also offers protection from certain side channels.

oyster incurs the following dependencies:
  * [libmbedtls-2.1.1](https://tls.mbed.org) for cryptographic primitives.
  * [libdrng-1.0](https://software.intel.com/en-us/articles/the-drng-library-and-manual): Intel's Digital Random Number Generator 

Since the operating system is untrusted, oyster does not use the C standard library because the C runtime directly depends on operating system services. 
This also reduces the size of our trusted computing base.

## Installation
 * Compilation: run `make` in the parent directory
 * Running: execute `bin/host_server_app` and `bin/host_client_app`

## Disclaimer
Work in progress, highly experimental.
Only tested on Linux x86-64.
When your program breaks, you get to keep both pieces. 
