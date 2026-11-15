//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_REACTOR_DESCRIPTOR_STATE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_REACTOR_DESCRIPTOR_STATE_HPP

#include <boost/corosio/native/detail/reactor/reactor_op_base.hpp>
#include <boost/corosio/native/detail/reactor/reactor_scheduler.hpp>

#include <boost/corosio/detail/conditionally_enabled_mutex.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

#include <errno.h>
#include <sys/socket.h>

namespace boost::corosio::detail {

/// Shared reactor event constants.
/// These match epoll numeric values; kqueue maps its events to the same.
static constexpr std::uint32_t reactor_event_read  = 0x001;
static constexpr std::uint32_t reactor_event_write = 0x004;
static constexpr std::uint32_t reactor_event_error = 0x008;

/** Per-descriptor state shared across reactor backends.

    Tracks pending operations for a file descriptor. The fd is registered
    once with the reactor and stays registered until closed. Uses deferred
    I/O: the reactor sets ready_events atomically, then enqueues this state.
    When popped by the scheduler, invoke_deferred_io() performs I/O under
    the mutex and queues completed ops.

    Non-template: uses reactor_op_base pointers so the scheduler and
    descriptor_state code exist as a single copy in the binary regardless
    of how many backends are compiled in.

    @par Thread Safety
    The mutex protects operation pointers and ready flags. ready_events_
    and is_enqueued_ are atomic for lock-free reactor access.
*/
struct reactor_descriptor_state : scheduler_op
{
    /// Protects operation pointers and ready/cancel flags.
    /// Becomes a no-op in single-threaded mode.
    conditionally_enabled_mutex mutex{true};

    /// Pending read operation (guarded by `mutex`).
    reactor_op_base* read_op = nullptr;

    /// Pending write operation (guarded by `mutex`).
    reactor_op_base* write_op = nullptr;

    /// Pending connect operation (guarded by `mutex`).
    reactor_op_base* connect_op = nullptr;

    /// Pending wait-for-read operation (guarded by `mutex`).
    reactor_op_base* wait_read_op = nullptr;

    /// Pending wait-for-write operation (guarded by `mutex`).
    reactor_op_base* wait_write_op = nullptr;

    /// Pending wait-for-error operation (guarded by `mutex`).
    reactor_op_base* wait_error_op = nullptr;

    /// True if a read edge event arrived before an op was registered.
    bool read_ready = false;

    /// True if a write edge event arrived before an op was registered.
    bool write_ready = false;

    /// Deferred read cancellation (IOCP-style cancel semantics).
    bool read_cancel_pending = false;

    /// Deferred write cancellation (IOCP-style cancel semantics).
    bool write_cancel_pending = false;

    /// Deferred connect cancellation (IOCP-style cancel semantics).
    bool connect_cancel_pending = false;

    /// Deferred wait-read cancellation (IOCP-style cancel semantics).
    bool wait_read_cancel_pending = false;

    /// Deferred wait-write cancellation (IOCP-style cancel semantics).
    bool wait_write_cancel_pending = false;

    /// Deferred wait-error cancellation (IOCP-style cancel semantics).
    bool wait_error_cancel_pending = false;

    /// Event mask set during registration (no mutex needed).
    std::uint32_t registered_events = 0;

    /// File descriptor this state tracks.
    int fd = -1;

    /// Accumulated ready events (set by reactor, read by scheduler).
    std::atomic<std::uint32_t> ready_events_{0};

    /// True while this state is queued in the scheduler's completed_ops.
    std::atomic<bool> is_enqueued_{false};

    /// Owning scheduler for posting completions.
    reactor_scheduler const* scheduler_ = nullptr;

    /// Prevents impl destruction while queued in the scheduler.
    std::shared_ptr<void> impl_ref_;

    /** Guards `retired_owner_`.

        A leaf lock: nothing else is locked while it is held. The
        scheduler takes it under its own mutex, and invoke_deferred_io()
        under `mutex`, so neither can take this state's `mutex` under the
        scheduler's mutex (a socket's op registration posts to the
        scheduler while holding `mutex`).
    */
    std::mutex retired_owner_mutex_;

    /** The owner of a closed descriptor, handed over by the scheduler.

        Set by keep_owner_if_enqueued() while the state is queued, and
        taken by the next invoke_deferred_io(), like `impl_ref_`.
    */
    std::shared_ptr<void> retired_owner_;

    /// Add ready events atomically.
    /// Release pairs with the consumer's acquire exchange on
    /// ready_events_ so the consumer sees all flags. On x86 (TSO)
    /// this compiles to the same LOCK OR as relaxed.
    void add_ready_events(std::uint32_t ev) noexcept
    {
        ready_events_.fetch_or(ev, std::memory_order_release);
    }

    /// Invoke deferred I/O and dispatch completions.
    void operator()() override
    {
        invoke_deferred_io();
    }

    /// Destroy without invoking.
    /// Called during scheduler::shutdown() drain. Clear impl_ref_ to break
    /// the self-referential cycle set by close_socket().
    void destroy() override
    {
        // Either reference may be the last one: release both only after
        // the last access to `*this`.
        std::shared_ptr<void> owner = std::move(impl_ref_);
        std::shared_ptr<void> retired;
        {
            std::lock_guard lock(retired_owner_mutex_);
            retired = std::move(retired_owner_);
        }
    }

    /** Keep @a owner alive while this state is queued.

        Called by reactor_scheduler::retire_descriptor() for a closed
        descriptor once no reactor pass can still hold it, under the
        scheduler's mutex. No runner can pop this state while that mutex
        is held, so if a pass queued it after the close looked at
        `is_enqueued_`, @a owner is in place before that queued state can
        be invoked (oramasearch/corosio#17: the owner used to be handed
        over after the scheduler's mutex was released, and a runner could
        invoke the state first, with no owner, while the last reference
        was dropped elsewhere).

        @param owner A strong reference to the object holding this state.

        @return @a owner, for the caller to drop after it has released the
            scheduler's mutex. When the state is queued it keeps a copy.
    */
    std::shared_ptr<void>
    keep_owner_if_enqueued(std::shared_ptr<void> owner) noexcept
    {
        if (!is_enqueued_.load(std::memory_order_acquire))
            return owner;
        {
            // A copy: once the state holds it, an invocation may take it
            // and drop it, and only @a owner keeps *this alive here.
            std::lock_guard lock(retired_owner_mutex_);
            retired_owner_ = owner;
        }
        if (!is_enqueued_.load(std::memory_order_acquire))
        {
            // An invocation of a state queued before the close cleared the
            // flag meanwhile; the close's own `impl_ref_` keeps that one
            // alive. Take the copy back if it did not see it, so it does
            // not stay here, holding the impl that holds it.
            std::lock_guard lock(retired_owner_mutex_);
            retired_owner_.reset(); // not the last reference: owner is one
        }
        return owner;
    }

    /** Perform deferred I/O and queue completions.

        Performs I/O under the mutex and queues completed ops. EAGAIN
        ops stay parked in their slot for re-delivery on the next
        edge event.
    */
    void invoke_deferred_io();
};

inline void
reactor_descriptor_state::invoke_deferred_io()
{
    std::shared_ptr<void> prevent_impl_destruction;
    op_queue local_ops;

    // Read under the mutex, used after it. Once the mutex is released,
    // nothing here may touch *this: with no owner and no completed op,
    // nothing keeps the impl alive, and a close and the drop of its last
    // reference on other runners can free it (corosio#17).
    reactor_scheduler const* scheduler = nullptr;

    {
        conditionally_enabled_mutex::scoped_lock lock(mutex);
        scheduler = scheduler_;

        // Must clear is_enqueued_ and move impl_ref_ under the same
        // lock that processes I/O. close_socket() checks is_enqueued_
        // under this mutex — without atomicity between the flag store
        // and the ref move, close_socket() could see is_enqueued_==false,
        // skip setting impl_ref_, and destroy the impl under us.
        prevent_impl_destruction = std::move(impl_ref_);
        is_enqueued_.store(false, std::memory_order_release);
        {
            // After clearing the flag: keep_owner_if_enqueued() checks it
            // again after storing, so an owner is either taken here or
            // taken back there (corosio#17).
            std::lock_guard owner_lock(retired_owner_mutex_);
            if (!prevent_impl_destruction)
                prevent_impl_destruction = std::move(retired_owner_);
            else
                retired_owner_.reset(); // same impl, not the last reference
        }

        std::uint32_t ev = ready_events_.exchange(0, std::memory_order_acquire);
        if (ev == 0)
        {
            // Mutex unlocks here; compensate for work_cleanup's decrement
            scheduler->compensating_work_started();
            return;
        }

        int err = 0;
        // True when the error event carried no socket error. A parked
        // read or write still fails with EIO (a hangup must surface, see
        // zetta#740), but a parked connect checks its own state instead:
        // epoll reports an open socket that has not started connecting
        // as EPOLLOUT|EPOLLHUP, and that event may have been recorded
        // before the connect started (oramasearch/corosio#10).
        bool error_without_cause = false;
        if (ev & reactor_event_error)
        {
            socklen_t len = sizeof(err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
                err = errno;
            if (err == 0)
            {
                err                 = EIO;
                error_without_cause = true;
            }
        }

        // Complete the parked connect, or leave it parked while the
        // socket is still connecting (perform_io() reports EAGAIN).
        auto finish_connect = [&]
        {
            auto* cn = connect_op;
            if (err && !error_without_cause)
                cn->complete(err, 0);
            else
                cn->perform_io();
            if (cn->errn == EAGAIN || cn->errn == EWOULDBLOCK)
            {
                cn->errn = 0;
                return;
            }
            connect_op = nullptr;
            local_ops.push(cn);
        };

        if (ev & reactor_event_read)
        {
            if (read_op)
            {
                auto* rd = read_op;
                if (err)
                    rd->complete(err, 0);
                else
                    rd->perform_io();

                if (rd->errn == EAGAIN || rd->errn == EWOULDBLOCK)
                {
                    rd->errn = 0;
                }
                else
                {
                    read_op = nullptr;
                    local_ops.push(rd);
                }
            }
            else
            {
                read_ready = true;
            }

            // Complete any parked wait-for-read regardless of read_op presence.
            if (wait_read_op)
            {
                wait_read_op->complete(err, 0);
                local_ops.push(std::exchange(wait_read_op, nullptr));
            }
        }
        if (ev & reactor_event_write)
        {
            bool had_write_op = (connect_op || write_op);
            if (connect_op)
                finish_connect();
            if (write_op)
            {
                auto* wr = write_op;
                if (err)
                    wr->complete(err, 0);
                else
                    wr->perform_io();

                if (wr->errn == EAGAIN || wr->errn == EWOULDBLOCK)
                {
                    wr->errn = 0;
                }
                else
                {
                    write_op = nullptr;
                    local_ops.push(wr);
                }
            }
            if (!had_write_op)
                write_ready = true;

            // Complete any parked wait-for-write regardless of write_op presence.
            if (wait_write_op)
            {
                wait_write_op->complete(err, 0);
                local_ops.push(std::exchange(wait_write_op, nullptr));
            }
        }
        // Complete a parked wait-for-error on any error condition.
        if ((ev & reactor_event_error) || err)
        {
            if (wait_error_op)
            {
                wait_error_op->complete(err, 0);
                local_ops.push(std::exchange(wait_error_op, nullptr));
            }
        }
        if (err)
        {
            if (read_op)
            {
                read_op->complete(err, 0);
                local_ops.push(std::exchange(read_op, nullptr));
            }
            if (write_op)
            {
                write_op->complete(err, 0);
                local_ops.push(std::exchange(write_op, nullptr));
            }
            if (connect_op)
                finish_connect();
            if (wait_read_op)
            {
                wait_read_op->complete(err, 0);
                local_ops.push(std::exchange(wait_read_op, nullptr));
            }
            if (wait_write_op)
            {
                wait_write_op->complete(err, 0);
                local_ops.push(std::exchange(wait_write_op, nullptr));
            }
        }
    }

    // Execute first handler inline — the scheduler's work_cleanup
    // accounts for this as the "consumed" work item
    scheduler_op* first = local_ops.pop();
    if (first)
    {
        scheduler->post_deferred_completions(local_ops);
        (*first)();
    }
    else
    {
        scheduler->compensating_work_started();
    }
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_REACTOR_DESCRIPTOR_STATE_HPP
