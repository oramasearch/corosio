# Posting a continuation reads only the continuation

Applies to `io_context::executor_type::post(capy::continuation&)` and `dispatch`. Fork change for
oramasearch/corosio#12, found by a downstream application.

## The problem

`post(continuation&)` has two paths. When the continuation is the `cont` member of a
`detail::continuation_op`, it queues the op itself, with no allocation. Otherwise it wraps the
handle in a heap-allocated op.

To tell them apart, it read a 4-byte tag 8 bytes before the continuation, where a
`continuation_op` keeps its tag. Capy hands the executor bare continuations too: `run_async`, and
the runners of the range `when_all` and `when_any`, which live in a
`std::make_unique<continuation[]>(count)` array. For the first element that read lands before the
heap block:

- **A fault.** When the block starts a page whose previous page is unmapped, the read faults. On
  macOS the nano allocator's zone starts at `0x600000000000`, so the application crashed at `0x5ffffffffff8`
  inside the launcher of a `when_all` over a vector of tasks.
- **A wrong answer.** When those 8 bytes happen to hold the tag `0xC0710A`, the bare continuation
  is queued as a `scheduler_op` it is not.

## The change

The mark now lives inside the continuation. `continuation_op`'s constructor points `cont.next` at a
private marker object that is never queued, and `try_from_continuation()` compares `c.next` with
it. It reads only `c`. The tag field is gone.

Capy's executors own `next` while a continuation is queued: the capy `thread_pool` and `strand` set
it to `nullptr` and link it. So a `continuation_op` whose `cont` was queued on one of them loses its
mark. A later post of it to an `io_context` takes the heap path. That is correct, only slower, and
the case is rare: a coroutine on a strand or pool posts to that executor, not to the `io_context`.

## Tests

`test/unit/continuation_post.cpp` (`boost.corosio.continuation_post`):

- A bare continuation at the start of a page behind a `PROT_NONE` page, posted through the concrete
  executor, through `capy::executor_ref`, and dispatched from outside `run()`. Before the change
  this died with SIGBUS on the first case.
- A bare continuation behind bytes that equal the old tag. Before the change this died with SIGSEGV.
- A `continuation_op` is still recognised; a bare continuation is not, whatever `next` holds.
- A `continuation_op` queued on a capy `thread_pool` first is still resumed by an `io_context`.
- `when_all` over vectors of 1 to 9 tasks on an `io_context`, the path the crash took.
