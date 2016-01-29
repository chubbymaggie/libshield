#include "platform.h"

platform_config_t platform_config;
extern void L_main();

void exit(uint64_t status)
{
  (void) status; //to supress unused parameter warning
  __asm("int3");
  while(1) { }
}

void yield()
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);
  __asm("movq %%rsp, %0":"=r"(platform_config.sir_rsp)::);
  __asm("movq %0, %%rsp"::"r"(platform_config.host_rsp):);
  __asm("popq %%r15":::);
  __asm("popq %%r14":::);
  __asm("popq %%r13":::);
  __asm("popq %%r12":::);
  __asm("popq %%rbx":::);
  __asm("popq %%rbp":::);
}

void sir_entry() 
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);
  __asm("movq %%rsp, %0":"=r"(platform_config.host_rsp)::);
  __asm("movq %0, %%rsp"::"r"(platform_config.sir_rsp):);
  __asm("popq %%r15":::);
  __asm("popq %%r14":::);
  __asm("popq %%r13":::);
  __asm("popq %%r12":::);
  __asm("popq %%rbx":::);
  __asm("popq %%rbp":::);
}

void sir_init(uint8_t *stack, uint8_t *heap, uint8_t *recv, uint8_t *send) 
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);

  __asm("movq %%rsp, %0":"=r"(platform_config.host_rsp)::);
  platform_config.sir_rsp = (uint64_t) stack + 1048568;
  __asm("movq %0, %%rsp"::"r"(platform_config.sir_rsp):);

  platform_config.stack_buf = (uint8_t *) platform_config.sir_rsp;
  platform_config.heap_buf = (uint8_t *) heap;
  platform_config.recv_buf = recv; 
  platform_config.send_buf = send;

  L_main();
}

