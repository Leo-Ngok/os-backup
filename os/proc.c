#include "proc.h"
#include "defs.h"
#include "loader.h"
#include "trap.h"
#include "vm.h"
#include "timer.h"

struct proc pool[NPROC];
__attribute__((aligned(16))) char kstack[NPROC][PAGE_SIZE];
__attribute__((aligned(4096))) char trapframe[NPROC][TRAP_PAGE_SIZE];

extern char boot_stack_top[]; // defined in entry.S
struct proc *current_proc;
struct proc idle;

int threadid()
{
	return curr_proc()->pid;
}

struct proc *curr_proc()
{
	return current_proc;
}

// initialize the proc table at boot time.
void proc_init(void)
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		p->state = UNUSED;
		p->kstack = (uint64)kstack[p - pool];
		p->trapframe = (struct trapframe *)trapframe[p - pool];
		/*
		* LAB1: you may need to initialize your new fields of proc here
		*/
	}
	idle.kstack = (uint64)boot_stack_top;
	idle.pid = 0;
	current_proc = &idle;
}

int allocpid()
{
	static int PID = 1;
	return PID++;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel.
// If there are no free procs, or a memory allocation fails, return 0.
struct proc *allocproc(void)
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		if (p->state == UNUSED) {
			goto found;
		}
	}
	return 0;

found:
	p->pid = allocpid();
	p->state = USED;
	p->pagetable = 0;
	p->ustack = 0;
	p->max_page = 0;
	memset(&p->context, 0, sizeof(p->context));
	memset((void *)p->kstack, 0, KSTACK_SIZE);
	memset((void *)p->trapframe, 0, TRAP_PAGE_SIZE);
	p->context.ra = (uint64)usertrapret;
	p->context.sp = p->kstack + KSTACK_SIZE;
	return p;
}

// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void scheduler(void)
{
	struct proc *p;
	for (;;) {
		for (p = pool; p < &pool[NPROC]; p++) {
			if (p->state == RUNNABLE) {
				/*
				* LAB1: you may need to init proc start time here
				*/
				p->state = RUNNING;
				current_proc = p;
				// Added in LAB1.
				// TODO: Warning: Do NOT try to run the process at midnight,
				// since the impl relys on time of day,
				// which means that might give a negative value.
				p->status = Running;
				p->start_cycle = get_time_m(); //get_cycle();
				if(p->init_cycle == 0)
					p->init_cycle = get_time_m();
				swtch(&idle.context, &p->context);
				p->total_cycles += get_time_m() - p->start_cycle;
			}
		}
	}
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
	struct proc *p = curr_proc();
	if (p->state == RUNNING)
		panic("sched running");
	swtch(&p->context, &idle.context);
}

// Give up the CPU for one scheduling round.
void yield(void)
{
	//current_proc->total_cycles += get_time_m()- current_proc->start_cycle;
	current_proc->state = RUNNABLE;
	current_proc->status = Ready;
	sched();
}

void freeproc(struct proc *p)
{
	p->state = UNUSED;
	// uvmfree(p->pagetable, p->max_page);
}

// Exit the current process.
void exit(int code)
{
	struct proc *p = curr_proc();
	infof("proc %d exit with %d", p->pid, code);
	freeproc(p);
	p->status = Exited;
	finished();
	sched();
}
