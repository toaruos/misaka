.global _start

_start:
  # Uh, different ABI...
  # pushq $main
  #call pre_main
  movq $0, %rdi # argc = 0
  movq $0, %rsi # argv = NULL
  call main


