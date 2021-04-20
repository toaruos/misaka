.global _start

_start:
  # Uh, different ABI...
  # pushq $main
  #call pre_main
  movq $main, %rdi
  movq $0, %rsi # argc = 0
  movq $0, %rdx # argv = NULL
  call pre_main


