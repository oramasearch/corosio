//
// Copyright (c) 2026 Michael Vandeberg
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_CONTINUATION_OP_HPP
#define BOOST_COROSIO_DETAIL_CONTINUATION_OP_HPP

#include <boost/corosio/detail/scheduler_op.hpp>
#include <boost/capy/continuation.hpp>

#include <atomic>
#include <cstddef>

namespace boost::corosio::detail {

/* Scheduler operation that resumes a capy::continuation.

   Embeds a continuation alongside a scheduler_op so the
   scheduler can queue it in the same FIFO as I/O completions
   without a heap allocation. The continuation lives in the
   caller's coroutine frame (awaitable or op struct); this
   wrapper gives it a scheduler_op identity.

   io_context::executor_type::post(continuation&) uses
   try_from_continuation() to recover the enclosing
   continuation_op. The mark is carried inside the
   continuation itself: the constructor points cont.next at
   a private marker object that no executor ever queues.
   A bare capy::continuation (capy's run_async, when_all and
   when_any runners) never holds that address, so the check
   reads only the continuation it was given. It used to read
   a tag 8 bytes before the continuation, which faulted when
   a bare continuation started a page whose previous page was
   unmapped, and could take a bare continuation for a
   continuation_op when those bytes happened to match.

   Executors own `next` while a continuation is queued. When
   a continuation_op's cont is posted to another executor
   (a capy thread_pool or strand), that executor overwrites
   the mark. A later post of the same continuation to an
   io_context then takes the heap-allocating fallback path,
   which is correct, only slower.
*/
struct continuation_op final : scheduler_op
{
    capy::continuation cont;

    continuation_op() noexcept : scheduler_op(&do_complete)
    {
        cont.next = marker();
    }

    // Reactor backends (epoll, select, kqueue) dispatch through
    // virtual operator()(). IOCP dispatches through func_ which
    // routes to do_complete below.
    void operator()() override
    {
        std::atomic_thread_fence(std::memory_order_acquire);
        cont.h.resume();
    }

    void destroy() override
    {
        if (cont.h)
            cont.h.destroy();
    }

private:
    // IOCP completion entry point. owner == nullptr means destroy.
    static void do_complete(
        void* owner,
        scheduler_op* base,
        std::uint32_t,
        std::uint32_t)
    {
        auto* self = static_cast<continuation_op*>(base);
        if (!owner)
        {
            if (self->cont.h)
                self->cont.h.destroy();
            return;
        }
        std::atomic_thread_fence(std::memory_order_acquire);
        self->cont.h.resume();
    }

public:

    // The address continuation_op stores in cont.next to mark
    // its continuation. Nothing ever queues this object, so no
    // executor links a continuation to it.
    static capy::continuation* marker() noexcept
    {
        static capy::continuation m;
        return &m;
    }

    // Recover the enclosing continuation_op from its cont member.
    // Returns nullptr if the continuation is not marked (a bare
    // capy::continuation from capy internals like run_async or
    // when_all, or a continuation_op whose mark another executor
    // overwrote). Reads only `c`.
    static continuation_op* try_from_continuation(
        capy::continuation& c) noexcept
    {
        if (c.next != marker())
            return nullptr;
        // offsetof on non-standard-layout is conditionally-supported;
        // suppress the warning — all targeted compilers handle this
        // correctly and the self-relative arithmetic is move-safe.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#endif
        constexpr auto cont_off = offsetof(continuation_op, cont);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        auto* base = reinterpret_cast<char*>(&c) - cont_off;
        return reinterpret_cast<continuation_op*>(base);
    }
};

} // namespace boost::corosio::detail

#endif
