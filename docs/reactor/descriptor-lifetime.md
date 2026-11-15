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
  deregistration can return it. The state keeps `self` in `impl_ref_` if it is
  queued, and drops it otherwise.
- **A pass running:** `self` goes on the scheduler's `retired_` list. When the
  pass ends (`do_one`, after `run_task` returns and the ready queue is spliced),
  the reactor thread applies the same rule to each retired state with the lock
  released. A state the pass queued keeps the impl alive until it is invoked;
  `invoke_deferred_io()` already releases `impl_ref_` there.

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
