#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	// YOUR CODE
	//val->sec = 0;
	//val->usec = 0;

	/* The code in `ch3` will leads to memory bugs*/

	uint64 cycle = get_cycle();
	uint64 val_paddr = useraddr(curr_proc()->pagetable, (uint64) val);
	TimeVal *paddr_val = (TimeVal *) val_paddr;
	paddr_val->sec = cycle / CPU_FREQ;
	paddr_val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	// val->sec = cycle / CPU_FREQ;
	// val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)




/*
* LAB1: you may need to define sys_task_info here
*/
int sys_task_info(struct TaskInfo *ti) {
	struct TaskInfo *pti = (struct TaskInfo *) useraddr(curr_proc()->pagetable, (uint64) ti);
	pti->status = curr_proc()->status;
	for(int i = 0; i < MAX_SYSCALL_NUM; ++i)
		pti->syscall_times[i] = curr_proc()->syscall_times[i];
	pti->time = get_time_m() - curr_proc()->init_cycle ;//* 1000 / CPU_FREQ;
	return 0;
}

int sys_mmap(void *start, size_t len, int prot, int flags, int fd) {
	if(prot > 7) {
		errorf("mmap: PROT_NONE is currently not supported");
		return -1;
	}
	if(prot == 0) {
		errorf("mmap: Specify protection level with argument prot.");
		return -1;
	}
	// Assignment specific: We don't use this in implementation.
	if(
		(  ((uint64) start) & (PAGE_SIZE - 1)  )
		!= 0) {
			errorf("`start` is not aligned to a multiple of PAGE_SIZE ( = 4096).\n \
			Note: This error is implementation specific. ");
			return -1;
		}
	int offset;
	for(offset = 0; offset < len; offset += PAGE_SIZE) {
		void *p_loc = kalloc();
		if(mappages(
			curr_proc()->pagetable, 
			(uint64) (  ((char*)start) + offset  ), 
			PAGE_SIZE, 
			(uint64) p_loc, 
			(prot << 1)| PTE_U) 
		< 0) {
			errorf("Remapping a mapped page.");
			return -1;
		}
	}
	return 0;
}
pte_t *walk(pagetable_t pagetable, uint64 va, int alloc);
int sys_munmap(void *start, size_t len) {
	int offset = 0;
	uint64 pa;
	for(; offset < len; offset += PAGE_SIZE) {
		uint64 va = (uint64) ((char *) start + offset);
		if((pa = useraddr(curr_proc()->pagetable, va)) == 0) {
			errorf("Attempt to unmap an unallocated page!");
			return -1; // No,
			// when there is no such address, just give back error
		}
		kfree((void *) pa);
		pte_t *remov_item = walk(curr_proc()->pagetable, va, 0);
		*remov_item = 0;
	}
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	curr_proc()->syscall_times[id]++;
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info( (struct TaskInfo *) args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap((void *) args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
