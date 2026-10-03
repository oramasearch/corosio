# Descriptor registration order and the work count

Applies to the kqueue and epoll backends. Fork change for oramasearch/corosio#7.

## The problem

`kqueue_scheduler::register_descriptor()` and `epoll_scheduler::register_descriptor()`
handed the descriptor state to the kernel (`EV_ADD` / `EPOLL_CTL_ADD`) first and
initialized it afterwards: `scheduler_`, `fd`, `registered_events`, the mutex's
enabled flag, `ready_events_`, and the ready flags.

A freshly registered socket is usually writable at once. With an `io_context` on
many runners, a reactor pass on another runner could return that event, queue the
state, and a third runner could invoke it, all before `register_descriptor()`
reached `desc->scheduler_ = this`. `invoke_deferred_io()` balances the work count
with `scheduler_->compensating_work_started()` when it runs no handler. With
`scheduler_` still null, that call found no thread context and did nothing. The
matching decrement in `work_cleanup` still happened, so each occurrence left
`outstanding_work_` one lower than the real amount of work.

The symptoms:

- the count reached zero while work was pending, so `run()` stopped early;
- in the end it was negative (-5 in the liquid#329 hang), and `do_one` never saw
  exactly zero, so `run()` never returned;
- the late `ready_events_.store(0)` could also erase an edge the pass had just
  recorded.

## The fix

Both backends now initialize the descriptor state completely before the
registration syscall. If the syscall fails, `registered_events` and `fd` are reset
so a later close does not deregister. select already initialized the state before
publishing it under the scheduler lock.

Two Debug assertions guard the invariant:

- `work_finished()` asserts that the count was positive. Every finish must match
  an earlier start.
- `compensating_work_started()` asserts that it found the calling thread's
  scheduler context.

## How it was found

Instrumentation of the liquid test was used:

- a per-operation ledger of starts, posts, finishes and consumptions;
- a check that each descriptor-state invocation paid for its consumption, either
  by compensating or by running an operation inline.

The reactor operations balanced. A few descriptor-state invocations paid
nothing, and each of them had `scheduler_ == nullptr`.

## Test

`boost.corosio.socket_stress.close_race` now runs twice:

- 4 runners with 256 lanes (64 on select);
- 16 runners with 64 lanes. Short, frequent reactor passes are what hit the window.

On the old code the 16-runner run trips the Debug assertion or ends early with
`reads != pairs`.
