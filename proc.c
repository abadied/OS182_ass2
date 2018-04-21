#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);
extern void start_sigret(void);
extern void end_sigret(void);
static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}


int 
allocpid(void) 
{
  pushcli();
  int pid;
  do{
    pid = nextpid;
   } while(!cas(&nextpid, pid, pid + 1));
  popcli();
  return pid;
}


//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  pushcli();

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(cas(&p->state, UNUSED, EMBRYO))
      goto found;

  popcli();

  return 0;

found:
  popcli();
  p->pid = allocpid();


  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  p->pend_signals = 0;
  p->signals_mask = 0;
  for(int i = 0; i<32 ; i++){
    p->signals_handlers[i] = (void*)SIG_DFL;
  } 
  p->stopped = 0;
  p->handling_signal = 0;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  for(int i = 0; i<32 ; i++){
    p->signals_handlers[i] = SIG_DFL;
  }

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  np->signals_mask = curproc->signals_mask;
  for(int i =0; i<32 ;i++){
    np->signals_handlers[i] = curproc->signals_handlers[i]; 
  }

  //acquire(&ptable.lock);

  //np->state = RUNNABLE;

  //release(&ptable.lock);
  pushcli();
  cas(&(np->state), EMBRYO, RUNNABLE);
  popcli();
  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  //acquire(&ptable.lock);
  pushcli();
  cas(&(curproc->state), curproc->state, MZOMBIE);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE || p->state == MZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  // curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  pushcli();
  for(;;){

    cas(&(curproc->state), RUNNING, MSLEEPING);

    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      while(p->state == MZOMBIE);
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        
        popcli();

        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      curproc->chan = 0;
      curproc->state = RUNNING;
      popcli();
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sched(); 
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    
    pushcli();

    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(!cas(&(p->state), RUNNABLE, MRUNNING))
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      cas(&(p->state), MSLEEPING, SLEEPING);
      cas(&(p->state), MRUNNABLE, RUNNABLE);

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;

      if (p->state == MZOMBIE){
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->killed = 0;
        p->chan = 0;
      }
      cas(&(p->state), MZOMBIE, ZOMBIE);

    }
    popcli();

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  // if(!holding(&ptable.lock))
  //   panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  pushcli();
  while(!cas(&(myproc()->state), RUNNING, MRUNNABLE));
  sched();
  popcli();
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  popcli();

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  pushcli();
  release(lk);
  // Go to sleep.
  p->chan = chan;
  cas(&(p->state), p->state, MSLEEPING);

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  popcli();
  acquire(lk);
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->chan == chan){
      if(cas(&p->state), MSLEEPING, MRUNNABLE)
        p->chan = 0;
      if(cas(&p->state), SLEEPING, MRUNNABLE){
        p->chan = 0;
        p->state = RUNNABLE;
      }
    }
  }
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  pushcli();
  wakeup1(chan);
  popcli();
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
// int
// kill(int pid)
// {
//   struct proc *p;

//   acquire(&ptable.lock);
//   for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
//     if(p->pid == pid){
//       p->killed = 1;
//       // Wake process from sleep if necessary.
//       if(p->state == SLEEPING)
//         p->state = RUNNABLE;
//       release(&ptable.lock);
//       return 0;
//     }
//   }
//   release(&ptable.lock);
//   return -1;
// }


int
kill(int pid, int signum)
{
  struct proc *p;

  pushcli();
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      if(signum == SIGKILL){
        p->killed = 1;
        // Wake process from sleep if necessary.
        if(p->state == SLEEPING)
          cas(&(p->state), SLEEPING, RUNNABLE);
        if(p->state == MSLEEPING)
          cas(&(p->state), MSLEEPING, MRUNNABLE);
      }
      else if(signum == SIGSTOP){
        p->stopped = 1;
      }
      else if(signum == SIGCONT){
        if(p->stopped != 0){
          p->pend_signals = p->pend_signals | (2 << SIGCONT);
        }
      }
      else{
        p->pend_signals = p->pend_signals | (2 << signum);
      }
      popcli();
      return 0;
    }
  }
  popcli();
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie",
  [MSLEEPING] "-sleep",
  [MRUNNABLE] "-runable",
  [MRUNNING]  "-run",
  [MZOMBIE]   "-zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}


uint
sigprocmask(uint sigmask){
  struct proc*  currproc;
  uint old_mask;
  currproc = myproc();
  old_mask = currproc->signals_mask;
  currproc->signals_mask = sigmask;
  return old_mask;
}

sighandler_t 
signal(int signum, sighandler_t handler){
  struct proc* currproc;
  sighandler_t old_handler;
  currproc = myproc();
  old_handler = currproc->signals_handlers[signum];
  currproc->signals_handlers[signum] = handler;
  return old_handler;
}

void
handle_signal(struct trapframe* tf){
  struct proc* p;
  if ((p=myproc()) == 0){
    return;
  }

  /** check for the users privates **/
  if (tf->cs & 3 != DPL_USER)
    return;

  while(p->stopped != 0){
    if(p->pend_signals & (2 << SIGCONT)){
      p->stopped = 0;
      acquire(&ptable.lock);
      p->pend_signals = p->pend_signals ^ (2 << SIGCONT);
      release(&ptable.lock);
    }
    else{
      yield();
    }
  }

  pushcli();
  if(!cas(&(p->handling_signal), 0, 1)){
    popcli();
    return;
  }

  if(p->pend_signals != 0){
    int sig = -1;
    for(int i = 0; i < 32; i++){
      if((p->pend_signals & (2 << i)) != 0 && (((2 << i) & p->signals_mask) == 0)){
        if ((int)p->signals_handlers[i] == SIG_IGN){
          p->pend_signals = p->pend_signals ^ (2 << i);
          continue;
        }
        sig = i;
        break;
      }
    }
    if(sig < 0){
      popcli();
      return;
    }

    p->pend_signals = p->pend_signals ^ (2 << sig);

    popcli();

    void* sig_handler = p->signals_handlers[sig];
    if ((int)sig_handler == SIG_DFL){
      kill(p->pid, SIGKILL);
    }
    else{
      p->user_tf_backup = *(p->tf);

      uint size = (uint)((&end_sigret) - (&start_sigret));
      p->tf->esp -= size;
      uint func_ptr = p->tf->esp;

      memmove((void*)(p->tf->esp), start_sigret, size);

      p->tf->esp -= 4;
      *((int*)(p->tf->esp)) = sig;

      p->tf->esp -= 4;
      *((int*)(p->tf->esp)) = func_ptr;

      p->tf->eip = (uint)sig_handler;
    }
    
  }
  return;
}

void
sigret(void){
  struct proc* p;

  if((p=myproc()) == 0)
    panic("should not be here");

  *(p->tf) = p->user_tf_backup;
  pushcli();
  cas(&(p->handling_signal), 1, 0);
  popcli();

  return;
}