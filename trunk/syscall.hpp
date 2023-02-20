#ifndef SYSCALL_HPP
#define SYSCALL_HPP

void HandleSysEnter(struct thread_state *ts, CONTEXT *ctx, 
		SYSCALL_STANDARD std);

void HandleSysExit(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT retval, ADDRINT err);

void DefaultSysExit(struct thread_state *ts, ADDRINT retval, 
		const struct syscall_desc *desc);

#endif
