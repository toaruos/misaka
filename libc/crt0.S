.global _start

_start:
  popq %rsi /* argc from stack */
  popq %rdx /* argv from stack */
  movq $main, %rdi /* address of main */
  call pre_main /* call pre_main */


