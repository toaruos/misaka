.global _start

_start:
  movq %rdx, %rcx /* env */
  movq %rsi, %rdx /* argv */
  movq %rdi, %rsi /* argc */
  movq $main, %rdi /* address of main */
  call pre_main /* call pre_main */


