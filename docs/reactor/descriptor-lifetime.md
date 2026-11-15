# Descriptor state lifetime across reactor passes

Applies to the reactor backends (kqueue, epoll, select). A change carried by this fork.

## The problem

Each socket and acceptor impl owns a `reactor_descriptor_state` as a member.
The kernel hands a raw pointer to it back to the reactor: kqueue through
`udata`, epoll through `data.ptr`, select through its descriptor snapshot. With
an `io_context` run on several threads, one thread runs the reactor pass
(`run_task`) with the scheduler lock released while the others run handlers.
From the moment `kevent()`/`epoll_wait()`/`select()` returns until the pass
splices its ready queue, the pass holds those pointers.

If another runner closes and destroys the socket in that window,
`reactor_socket_service::destroy()` drops the last owning `shared_ptr` and the
impl, with its descriptor state, is freed. The close only kept the impl alive
when `is_enqueued_` was already set, so a pass that queued the state after the
close looked at the flag left a freed state in the scheduler queue. The next
`invoke_deferred_io()` locked a destroyed mutex (`std::system_error: mutex lock
failed`), or the pass itself wrote to freed memory in `add_ready_events()`.

## The fix

Closing a registered descriptor (`do_close_socket()` and `do_release_socket()`
on sockets and acceptors) ends with
`reactor_scheduler::retire_descriptor(desc_state_, self)`, after the descriptor
has been deregistered. Under the scheduler lock:

- **No pass running:** no pass can hold the state, and none started after the
  deregistration can return it. The state keeps `self` if it is queued, and
  `self` is dropped otherwise.
- **A pass running:** `self` goes on the scheduler's `retired_` list. When the
  pass ends (`do_one`, after `run_task` returns and the ready queue is spliced),
  the reactor thread applies the same rule to each retired state. A state the
  pass queued keeps the impl alive until it is invoked; `invoke_deferred_io()`
  takes the owner and releases it there.

In both cases "is it queued?" is decided, and the owner handed over, while the
scheduler lock is still held (oramasearch/corosio#17). The scheduler's own
references are dropped after the lock is released.

So a descriptor state is never freed while a pass may hold it: the impl
outlives the pass, then outlives any queued invocation.

### Why this shape

The issue offered two options: close keeps the impl alive and releases it
through an op queued behind the current pass, or `destroy()` defers the erase
until after the next pass. This fix uses the first option's ownership, with
the release tied to the end of the pass instead of to a queued op:

- A queued release op is not ordered against the descriptor state's own
  invocation on another runner, and does not know whether the pass queued the
  state at all. The end of the pass is the one point where both are settled.
- Deferring `destroy()`'s erase would still need the same per-state check
  ("did the pass queue it?"), and would spread pass bookkeeping into every
  socket service.
- One place, `reactor_scheduler::do_one`, covers all three reactor backends.
  When no close races a pass the cost is a lock per close and an `empty()`
  check per pass.

If memory runs out while recording a retired state, the impl is pinned in
`impl_ref_`: it leaks until the scheduler shuts down rather than risk a
use-after-free.

## Two reads of a freed state under load (corosio#17)

AddressSanitizer reported a heap-use-after-free in `invoke_deferred_io()`
running liquid's `RuntimeSockets.ConcurrentOpenAndCloseInsideBlockOn` (64 lanes
of the same shape as `close_race`, inside short-lived multi-runner contexts), in
17 of 400 processes at `--gtest_repeat=10`. Two windows let an invocation run
inside an impl that nothing kept alive.

### The state was read after its mutex was released

`invoke_deferred_io()` read `scheduler_` from the state after releasing the
state's mutex, to post the other completions or, when nothing completed, to
balance the work count. An invocation that completed nothing has no op (and so
no op `impl_ptr`) keeping the impl alive, and if it started while the socket was
still open it holds no owner either. A close on another runner, and the drop of
the last reference on a third (the retired owner, or a cancelled op's
`impl_ptr`), could free the impl in that window. It now reads `scheduler_` while
it holds the mutex and touches nothing of the state after releasing it.

### The owner was handed over after the scheduler lock was released

The first version of this fix released the scheduler lock, then handed each
retired owner to its state. The pass had just spliced its ready queue, so in
that window another runner could pop a state the pass queued after the close,
enter `invoke_deferred_io()` with an empty `impl_ref_` and clear `is_enqueued_`.
The hand-over then saw the flag clear and dropped the owner while the invocation
was still inside the impl. The no-pass path of `retire_descriptor()` had the
same window between its `task_running_` check and the hand-over.

Now `reactor_descriptor_state::keep_owner_if_enqueued()` runs under the
scheduler lock on both paths, so no runner can pop the state before its owner
is there:

- A copy of the owner goes into `retired_owner_`, guarded by
  `retired_owner_mutex_`, not into `impl_ref_`. `impl_ref_` is guarded by the
  state's `mutex`, and that mutex cannot be taken under the scheduler lock: a
  socket's op registration posts to the scheduler while holding it, so the order
  would invert. `retired_owner_mutex_` is a leaf lock; nothing else is taken
  while it is held.
- The scheduler keeps its own reference until the hand-over is done, and drops
  it after releasing its lock: once the state holds the copy, an invocation may
  take it and drop it, and the scheduler's reference keeps the state alive until
  the hand-over returns.
- `invoke_deferred_io()` clears `is_enqueued_`, then takes `retired_owner_`
  under the leaf lock (or drops it, if `impl_ref_` already held the same impl).
- `keep_owner_if_enqueued()` stores the copy, then checks `is_enqueued_` again.
  If an invocation of a state queued before the close cleared it meanwhile, it
  takes the copy back, so it is never left in a state that holds the impl that
  holds it. That invocation is kept alive by the close's own `impl_ref_`.
- `destroy()` releases both references.

## Related fixes in the same change

- `do_one` re-takes the scheduler lock when `run_task` returns without it
  (select's `EINTR`/`EBADF` retry path). The pass end, and the push of the task
  sentinel, now always happen under the lock.
- `select_scheduler::run_task` takes the lock before snapshotting
  `registered_descs_`. `do_one` releases it before a zero-timeout poll, so the
  snapshot read the map while other runners registered and deregistered.

## Test

`boost.corosio.socket_stress.close_race.{kqueue,epoll,select}` in
`test/unit/socket_stress.cpp` runs an `io_context` on four threads with 256
lanes (64 on select, which caps descriptors at `FD_SETSIZE`), then on 16 threads
with 64 lanes (added for #7, see `register-ordering.md`). Each lane opens a
connected pair, parks a read on one end, writes to the other and closes it,
without waiting for the reader. The reader destroys its socket on whichever
runner resumed it, while the writes and the hang-up are still producing events.
Without the fix it aborts with `mutex lock failed`, a crash, or an
AddressSanitizer use-after-free in most one-second runs.

Notes on the test's shape:

- The number of live readers is capped, and a lane at the cap yields by
  re-posting itself rather than waiting on a timer. Timers used on runner
  threads leave entries in the timer service's per-thread caches when those
  threads exit, which LeakSanitizer reports on Linux.
- The stop signal comes from a plain thread for the same reason.
- `connect_pair()` adopts descriptors without setting `SO_NOSIGPIPE`, so on
  macOS the test sets it on the writer itself. A write to a pair whose reader
  has closed otherwise raises `SIGPIPE`.
