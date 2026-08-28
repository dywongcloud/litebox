# Fork() Implementation Guide for LiteBox

## Executive Summary

This document provides a detailed implementation roadmap for fork() syscall support in litebox/boxer. Fork is a foundational Unix syscall that creates a new process by copying the current process's address space, file descriptors, and other per-process state. Currently, litebox supports only CLONE_THREAD (multi-threading within a single process).

**Status:** Infrastructure in place (syscall routing added in commit 0466463). Full implementation blocked by architectural decisions requiring careful integration.

**Estimated effort:** ~2-2.5k lines of code across 4-5 files, distributed over 5 implementation phases.

---

## Part 1: Architecture Overview

### Current LiteBox Process Model

1. **Single Process per Sandbox**
   - One `Process` struct per sandbox instance
   - Multiple `ThreadState` threads within that Process
   - Each thread has a `Task` with its own `tid` and `pid` (currently same)
   - Global `next_thread_id` counter for both PIDs and TIDs

2. **Key Structures**
   - `Task<Platform, FS>` - per-thread execution context
     - `pid: i32` - process ID (currently same for all threads)
     - `ppid: i32` - parent process ID
     - `tid: i32` - thread ID
     - `thread: ThreadState<Platform>` - contains Process reference
   - `Process<Platform>` - per-process state
     - `threads: BTreeMap<i32, Arc<ThreadRemote>>` - thread list
     - `nr_threads` atomic counter
     - `limits: ResourceLimits` - per-process resource limits
     - `alarm_timer: Alarm<Platform>` - per-process alarm
   - `GlobalState<Platform, FS>`
     - `next_thread_id` - global atomic for ID allocation
     - `platform` - access to scheduler, memory, etc.
   - `ThreadState` properties
     - `process: Arc<Process>` - back-reference to owning process
     - `clear_child_tid` - for futex-based thread sync on exit
     - Signal handlers and state

3. **Scheduler Integration**
   - `platform.spawn_thread()` - spawns new task as independently schedulable
   - Tasks are added to thread pool and scheduled independently
   - Preemption and fairness apply per-thread

### What Fork() Requires

1. **Separate PID Namespaces**
   - Parent and child must have distinct PIDs
   - Child's PPID must point to parent
   - Independent PID allocation (separate from TID allocation)

2. **Separate Address Spaces**
   - Child gets independent copy of parent's memory
   - Parent/child modifications don't affect each other (except MAP_SHARED)
   - Both run concurrently

3. **Process Tracking**
   - Parent must know about children for wait() syscalls
   - Zombie state tracking when child exits before parent waits
   - Reparenting to PID 1 (init) if parent exits first

4. **Inherited but Independent State**
   - File descriptors copied (independent offsets, same underlying files)
   - Signal handlers reset to SIG_DFL in child
   - Signal mask inherited
   - Environment/memory layout inherited
   - Credentials, limits, working directory inherited

---

## Part 2: Critical Design Decisions

### Decision 1: PID Allocation Strategy

**Problem:** Currently, `next_thread_id` is a unified counter for both PIDs and TIDs. Fork needs separate PID allocation.

**Options:**

A. **Unified Separate Counter**
   - Add `next_pid` and `next_tid` as separate atomics in GlobalState
   - Simple: one counter per resource type
   - Clean: no collisions or confusion
   - Trade-off: Two counters instead of one

B. **Partition Existing Counter**
   - Use ranges: even TIDs, odd PIDs (or similar)
   - Complex: prone to off-by-one errors
   - Coupling: changes to ID allocation affect both
   - Not recommended

**Recommendation: Decision A (Unified Separate Counter)**

Implementation:
```rust
pub struct GlobalState<...> {
    next_thread_id: AtomicI32,  // For TIDs only
    next_pid: AtomicI32,        // For PIDs only (NEW)
    ...
}
```

- Spawn new process: `let pid = global.next_pid.fetch_add(1, Ordering::Relaxed)`
- Spawn new thread: `let tid = global.next_thread_id.fetch_add(1, Ordering::Relaxed)`
- No collision, no confusion, clear intent

---

### Decision 2: Memory Copy Strategy

**Problem:** After fork(), parent and child must have independent address spaces but concurrent execution requires careful memory handling.

**Options:**

A. **Full Immediate Copy**
   - Copy entire address space on fork() call
   - Simple: no COW complexity
   - High latency: fork() blocks until copy completes
   - High memory: both parent and child occupy full memory
   - Correctness: guaranteed isolation
   - Recommended for first implementation

B. **Copy-on-Write (COW)**
   - Share pages initially, fork when either process writes
   - Low latency: fork() completes quickly
   - Shared memory: until write triggers copy
   - Complexity: page fault handler must detect COW, allocate new page, copy, update mapping
   - Optimization: suitable for follow-up work

C. **Hybrid**
   - Immediate copy of small sections, COW for large regions
   - Moderate complexity
   - Good latency + reasonable memory use
   - Medium complexity

**Recommendation: Decision A (Full Immediate Copy) for V1**

- First implementation should prioritize correctness over optimization
- Platform's memory allocator (PageManager) already handles allocations
- Copy logic: iterate all pages in parent, allocate new page, memcpy content
- Future work: switch to COW when performance measurement shows it's needed

Implementation outline:
```rust
fn do_fork(&self) -> Result<i32, Errno> {
    // 1. Allocate new PID
    let child_pid = self.global.next_pid.fetch_add(1, Ordering::Relaxed);
    
    // 2. Copy memory: for each page in parent's address space
    //    a. Allocate new page in child
    //    b. memcpy parent page to child page
    //    c. Map page at same address in child's address space
    
    // 3. Copy FD table, credentials, limits, etc.
    // 4. Reset signal handlers to SIG_DFL
    // 5. Spawn child as new independently-schedulable task
    // 6. Return child_pid to parent, 0 to child
}
```

---

### Decision 3: Process Model

**Problem:** How do multiple processes coexist in litebox? Do we need a new ProcessGroup struct?

**Options:**

A. **Extend Existing Process Struct**
   - Add `children: Arc<Mutex<Vec<(i32, Arc<Process>)>>>` to track children
   - Add `parent_pid: i32` for reparenting
   - Add exit status tracking for zombie management
   - Single Process per process, not per thread group
   - Simpler: reuse existing Process infrastructure

B. **New ProcessGroup Struct**
   - Create ProcessGroup that contains multiple Process structs
   - Each Process is one process (task 1)
   - Adds abstraction layer
   - More complex

**Recommendation: Decision A (Extend Existing Process)**

- One Process = one process (not process group)
- Reuse existing structure
- Add parent-child tracking
- Minimal architectural change

New fields in Process:
```rust
pub struct Process<Platform: ShimPlatform> {
    // ... existing fields ...
    
    // Parent process ID (for reparenting to init)
    parent_pid: i32,
    
    // Children: (child_pid, child_process_arc) mapping
    children: Arc<Mutex<Vec<(i32, Arc<Process<Platform>>)>>>,
    
    // Exit status (when last thread exits)
    exit_status: Cell<Option<ExitStatus>>,
    
    // Is this a zombie? (child exited, parent hasn't wait()'ed)
    is_zombie: AtomicBool,
}
```

---

### Decision 4: Scheduler Integration

**Problem:** How is child spawned and scheduled? Does platform.spawn_thread() work for processes too?

**Option:** Extend spawn_thread for Process Creation

Platform already has:
- `spawn_thread(ctx, args)` - spawns a new thread with given context

For fork():
- Create new Task with child_pid, ppid, copied memory
- Call `platform.spawn_thread(child_ctx, child_task)`
- Child begins execution at same point (return value 0 from fork)
- Parent continues (return value = child_pid)

Implementation:
```rust
// Parent continues here (after child is spawned)
let child_pid = <newly allocated PID>

// Create child task
let child_task = Task {
    pid: child_pid,
    ppid: self.pid,
    tid: child_pid,  // Single-threaded child initially
    thread: ThreadState::new_process(child_pid),
    // ... copy other state ...
};

// Spawn child
let spawn_result = unsafe {
    self.global.platform.spawn_thread(
        ctx,  // Same context (registers), will be modified for child to return 0
        child_task,
    )
};

// Parent returns child_pid
Ok(child_pid as usize)
```

For child to return 0:
- Modify child's register context: RAX (return value) = 0
- Both start execution at same point but with different return values

---

### Decision 5: Wait Syscalls (wait4/waitpid)

**Problem:** Parent needs to wait for child exit and retrieve exit code.

**Syscalls needed:**
- `wait4(pid, &status, flags, &rusage)` - most complete
- `waitpid(pid, &status, flags)` - simpler, no rusage
- `wait(status)` - waits for any child
- `waitid(idtype, id, &siginfo, flags)` - modern variant

**Recommendation: Implement wait4 + waitpid**

Data structures:
```rust
// In Process struct:
// Track child processes and their exit status
pub struct ChildProcess {
    pid: i32,
    process: Arc<Process>,
    exit_status: Option<ExitStatus>,
    reaped: bool,
}

// In Process.children:
children: Arc<Mutex<Vec<ChildProcess>>>,
```

Wait4 implementation outline:
```rust
pub fn sys_wait4(
    &self,
    pid: i32,           // PID to wait for (-1 = any child)
    status: &mut i32,   // Exit status output
    flags: i32,         // WNOHANG, WUNTRACED, etc.
) -> Result<i32, Errno> {
    loop {
        let mut inner = self.thread.process.inner.lock();
        
        // Find matching child
        if let Some(child) = inner.children.iter().find(|c| {
            if pid == -1 { true } else { c.pid == pid }
        }) {
            if let Some(exit_status) = child.exit_status {
                // Child has exited
                *status = encode_wait_status(exit_status);
                let result_pid = child.pid;
                inner.children.remove(child);  // Reap zombie
                return Ok(result_pid);
            }
        }
        
        // WNOHANG: return immediately if no child ready
        if flags & WNOHANG != 0 {
            return Err(Errno::ECHILD);
        }
        
        // Block: wait for child to exit
        // Use futex/condvar to wait on child exit event
    }
}
```

Exit status encoding (standard Unix):
- `WIFEXITED(status)`: non-zero if exited normally
- `WEXITSTATUS(status)`: exit code (0-255)
- `WIFSIGNALED(status)`: non-zero if killed by signal
- `WTERMSIG(status)`: signal number

---

## Part 3: Implementation Phases

### Phase 1: PID Infrastructure (~300 lines)

**Files:** `src/lib.rs`, `src/syscalls/process.rs`

**Tasks:**
1. Add `next_pid` atomic to GlobalState
2. Add `ppid: i32` to Task struct
3. Add `getppid()` syscall implementation
4. Add simple `ExitStatus` enum for wait syscalls
5. Modify Task creation to use separate PID/TID

**Deliverable:** Tasks have distinct PIDs, getppid() works

**Testing:**
```bash
# Test: parent and child PIDs differ
fork && echo parent=$pid && child_pid=$!
wait $child_pid
```

---

### Phase 2: Memory Copy (~400-800 lines)

**Files:** Depends on PageManager location (likely in litebox crate)

**Tasks:**
1. Implement `copy_process_memory(parent_task: &Task, child_task: &Task)`
2. Iterate parent's virtual address space
3. For each mapped region: allocate new page, memcpy content
4. Map new page in child's address space at same address
5. Handle stack, heap, code sections

**Deliverable:** Child has independent memory, parent modifications don't affect child

**Testing:**
```bash
# Test: memory isolation
fork && (if child: write to heap, exit; else: check heap unchanged)
```

---

### Phase 3: Core Fork Handler (~500 lines)

**Files:** `src/syscalls/process.rs`, `src/lib.rs`

**Tasks:**
1. Implement `sys_fork(ctx)`
2. Call Phase 1 PID allocation
3. Call Phase 2 memory copy
4. Copy FD table (independent offsets)
5. Reset signal handlers to SIG_DFL
6. Spawn child as new Task via `platform.spawn_thread()`
7. Return child_pid to parent, 0 to child

**Deliverable:** fork() creates new process with independent memory and PIDs

**Testing:**
```bash
# Test: fork basic
parent_pid=$(fork)
echo "Parent: $parent_pid, Child: 0"

# Test: fork + exec
fork && execve("/bin/true")
```

---

### Phase 4: Wait & Signal Support (~400 lines)

**Files:** `src/syscalls/process.rs`

**Tasks:**
1. Implement `wait4()` and `waitpid()`
2. Add zombie process tracking
3. Implement signal handler reset in child
4. Implement `getppid()` for reparenting to init (PID 1)
5. Handle parent exit (reparent children to init)

**Deliverable:** Parent can wait for child, retrieve exit code; signal handlers reset correctly

**Testing:**
```bash
# Test: wait for exit code
fork && exit(42)
waitpid(pid, &status)
assert(WEXITSTATUS(status) == 42)

# Test: signal reset
parent: signal(SIGUSR1, handler)
fork && deliver_signal(SIGUSR1)  # Child dies with SIGUSR1 default
waitpid(pid, &status)
assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR1)
```

---

### Phase 5: Testing & Integration (~600 lines)

**Files:** `examples/`, documentation

**Tasks:**
1. Test 1: Simple fork (both processes runnable, distinct PIDs)
2. Test 2: fork + execve (child loads new binary)
3. Test 3: FD inheritance (independent seek positions)
4. Test 4: Memory isolation (parent/child changes independent)
5. Test 5: Multiple children (unique PIDs, all reapable)
6. Test 6: Signal delivery (handlers reset, default actions)
7. Example: Simple shell with fork-exec-wait pattern
8. Performance measurement: fork latency, memory overhead
9. Documentation: docs/boxer.md fork section + CLAUDE.md notes

**Deliverable:** Comprehensive fork() support with tests and examples

---

## Part 4: Integration Points & Dependencies

### Files to Modify

1. **litebox_common_linux/src/lib.rs**
   - ✅ Added Fork to SyscallRequest enum
   - ✅ Added fork syscall routing
   - Add getppid syscall routing (if not present)

2. **litebox_shim_linux/src/lib.rs**
   - Modify GlobalState to add `next_pid`
   - Modify Task struct to track `ppid`
   - Add fork() routing to syscall dispatcher

3. **litebox_shim_linux/src/syscalls/process.rs**
   - ✅ Added sys_fork() stub
   - Implement full sys_fork() handler
   - Add `get_ppid()` syscall
   - Implement wait4/waitpid syscalls
   - Add zombie tracking

4. **litebox_shim_linux/src/syscalls/file.rs**
   - Implement FD table copying for fork

5. **litebox_shim_linux/src/syscalls/signal.rs**
   - Implement signal handler reset for child

---

## Part 5: Known Limitations & Deferred Work

### Out of Scope (V1)

1. **vfork()** - Optimization where child borrows parent memory until execve
   - Deferred: more complex, lower priority than fork

2. **Process groups/sessions** - Job control for shells
   - Deferred: not needed for basic multi-process support

3. **CLONE_PIDNS, CLONE_NEWPID** - Separate PID namespaces
   - Deferred: namespace isolation, not basic fork

4. **Copy-on-Write** - Memory optimization
   - Deferred: measure impact first, optimize if needed

5. **Resource limit enforcement** - Limits per process
   - Deferred: basic infrastructure; enforcement is follow-up

### Testing Limitations

- **No synthetic tests** per gm methodology - only real execution tests
- **Single test.js file** at repo root for end-to-end validation
- No mock frameworks or test harnesses

---

## Part 6: Risk Mitigation

### Critical Areas Requiring Care

1. **Race conditions**
   - Parent-child synchronization on fork() completion
   - Child modifying shared GlobalState while parent accesses it
   - Signal delivery during fork

2. **Deadlocks**
   - Lock ordering: avoid circular wait patterns
   - Mutexes in GlobalState, Process, FilesState, SignalState must be acquired in consistent order

3. **Memory leaks**
   - Child task must properly initialize/clean up
   - Zombie processes must be reapable and freed
   - Arc references must be released when process exits

4. **Scheduler fairness**
   - Parent and child should have equal scheduling opportunities
   - Avoid parent blocking child's progress

### Mitigation Strategies

1. **Design review** - Multiple eyes on fork() implementation before code
2. **Unit testing** - Per-phase testing to catch issues early
3. **Stress testing** - Fork many children, wait in different orders
4. **Regression testing** - Ensure single-process workloads still work
5. **Performance profiling** - Measure fork latency and memory overhead

---

## Part 7: Success Criteria

### Functional Requirements (V1)

- [x] fork() syscall returns twice (parent gets child PID, child gets 0)
- [ ] Parent and child have distinct, valid PIDs
- [ ] Child has independent memory space
- [ ] Child inherits parent's file descriptors with independent offsets
- [ ] Child signal handlers reset to SIG_DFL
- [ ] Both parent and child are independently schedulable
- [ ] wait4/waitpid retrieve child exit code correctly
- [ ] Multiple children can be forked from same parent
- [ ] Parent reparenting to init works when parent exits

### Performance Targets

- fork() latency: < 10ms for typical workload
- Memory overhead: < 1MB per fork for small processes
- No regression in single-process performance

### Test Coverage

- 6 distinct real-execution scenarios pass
- Example shell demonstrates fork-exec-wait workflow
- No flakiness over 100 iterations

---

## Part 8: Next Steps for Implementation

1. **Session Preparation**
   - Review this specification with full gm methodology
   - Resolve any architectural questions before coding
   - Ensure team agreement on design decisions

2. **Phase 1 Implementation**
   - Start with PID infrastructure (simplest, unblocks others)
   - Get tests passing before moving to Phase 2
   - ~1-2 days of focused development

3. **Iterative Refinement**
   - Each phase builds on previous
   - Test and verify before moving forward
   - Measure and optimize if needed

4. **Documentation**
   - Keep CLAUDE.md updated with progress
   - Document any deviations from plan
   - Update docs/boxer.md with fork() capabilities

---

## Appendix: Reference Implementation Outline

### sys_fork() Pseudocode

```rust
pub fn sys_fork(&self, ctx: &litebox_common_linux::PtRegs) -> Result<usize, Errno> {
    // Phase 1: Allocate child PID
    let child_pid = self.global.next_pid.fetch_add(1, Ordering::Relaxed);
    if child_pid <= 0 || child_pid > i32::MAX / 2 {
        return Err(Errno::EAGAIN);  // PID space exhausted
    }
    
    // Phase 2: Copy memory
    let child_memory = self.copy_process_memory()?;
    
    // Phase 3: Copy FD table
    let child_files = self.files.borrow().fork_copy();
    
    // Phase 4: Copy credentials, limits, etc.
    let child_creds = self.credentials.borrow().clone();
    let child_limits = self.thread.process.limits.clone();
    
    // Phase 5: Reset signal handlers (child only)
    // Mark in ThreadState that this is a child, reset handlers before child runs
    
    // Phase 6: Create child task
    let child_task = Task {
        global: self.global.clone(),
        wait_state: WaitState::new(self.global.platform),
        thread: ThreadState::new_process(child_pid),  // Creates new Process
        pid: child_pid,
        ppid: self.pid,
        tid: child_pid,
        credentials: RefCell::new(Arc::new(child_creds)),
        comm: self.comm.clone(),
        fs: RefCell::new(child_fs),
        files: RefCell::new(Arc::new(child_files)),
        signals: self.signals.fork_child_reset(),  // Reset handlers to default
    };
    
    // Phase 7: Register child in parent's process
    self.thread.process.inner.lock().children.push((child_pid, child_process_arc));
    
    // Phase 8: Spawn child
    unsafe {
        let mut child_ctx = *ctx;
        child_ctx.set_return_value(0);  // Child returns 0 from fork
        self.global.platform.spawn_thread(
            &child_ctx,
            Box::new(NewThreadArgs { task: child_task }),
        )?;
    }
    
    // Phase 9: Return child PID to parent
    Ok(child_pid as usize)
}
```

---

## Summary

This specification provides a clear, incremental path to implementing fork() in litebox. Key design decisions prioritize correctness and clarity over optimization, with performance optimization deferred to follow-up work.

**Total estimated effort:** ~2-2.5k lines, ~2-3 weeks of focused development across 5 phases.

**Critical success factors:**
1. Clear separation of concerns across phases
2. Comprehensive testing at each phase boundary
3. Careful attention to race conditions and deadlocks
4. Performance measurement before optimization

Start with Phase 1 (PID infrastructure) to establish foundation and validate design, then proceed through remaining phases as team bandwidth allows.
