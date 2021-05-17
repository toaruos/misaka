#pragma once

extern long arch_syscall_number(struct regs * r);
extern long arch_syscall_arg0(struct regs * r);
extern long arch_syscall_arg1(struct regs * r);
extern long arch_syscall_arg2(struct regs * r);
extern long arch_syscall_arg3(struct regs * r);
extern long arch_syscall_arg4(struct regs * r);

extern long arch_stack_pointer(struct regs * r);
extern long arch_user_ip(struct regs * r);

extern void arch_syscall_return(struct regs * r, long retval);
