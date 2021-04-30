.global _start

_start:
  movq %rdx, %rcx /* env */
  movq %rsi, %rdx /* argv */
  movq %rdi, %rsi /* argc */
  movq $main, %rdi /* address of main */
  and $0xFFFFFFFFFFFFFFF0, %rsp
  call pre_main /* call pre_main */


