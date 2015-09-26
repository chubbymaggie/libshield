OUTPUT_FORMAT("elf64-x86-64")

ENTRY(_start)

SECTIONS
{
   . = 0x07000000; .crypto_heap ALIGN(0x1000) : { *(.crypto_heap) }
   . = 0x07000000; .enclave_base  ALIGN(0x1000) : { *(.enclave_base) }
   . = 0x08000000; .secs  ALIGN(0x1000) : { *(.secs) }
   . = 0x08001000; .tcs   ALIGN(0x1000) : { *(.tcs) }
   . = 0x08011000; .stack ALIGN(0x1000) : { *(.stack) }
   . = 0x08012000; .text  ALIGN(0x1000) : { *(.text) }
   . = 0x08022000; .data  ALIGN(0x1000) : { *(.data) }
   . = 0x08022000; .enclave_high  ALIGN(0x1000) : { *(.enclave_high) }
}
