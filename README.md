# oyster
oyster is a runtime library for programming secure isolated regions (SIRs).
oyster provides core primitives such as memory management (available via malloc and free APIs) and secure communication channel (available via send and recv APIs).
oyster Currently supports
  * Secure channel estanlishment using Diffie-Hellman-Merkle protocol for symmetric key exchange
  * Send and Recieve operations for arbitrary sized data on the secure channelS
  * Malloc and Free operations for arbitrary sized regions

oyster depends on the mbedTLS library, and does not use the C standard library to avoid depending on OS services.

## Installation
 * [Compilation](run make in the parent directory)
 * [Running](run bin/app_host)

## Disclaimer
Work in progress, highly experimental.
When your program breaks, you get to keep both pieces. 
