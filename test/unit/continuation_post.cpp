//
// Copyright (c) 2026 Steve Sperandeo
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// Posting a bare capy::continuation reads only the continuation
//
// io_context::executor_type::post(continuation&) asks whether the
// continuation is the cont member of a continuation_op. It used to answer
// by reading a tag 8 bytes before the continuation. Capy's range when_all
// and when_any post bare continuations from a heap array, so for the first
// element that read landed before the block: it faulted when the block
// started a page whose previous page was unmapped (a segfault at
// 0x5ffffffffff8, the start of the macOS nano zone minus 8), and it took
// the continuation for a continuation_op when those bytes held the tag.
// These tests place a bare continuation at the start of a page behind a
// guard page, and behind bytes that equal the old tag, and post it through
// the concrete and the type-erased executor.

#include <boost/corosio/io_context.hpp>

#include <boost/corosio/detail/continuation_op.hpp>

#include <boost/capy/continuation.hpp>
#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/thread_pool.hpp>
#include <boost/capy/io_result.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>

#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <new>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "test_suite.hpp"

namespace boost::corosio {

namespace {

// A coroutine that counts its resumption, then finishes.
struct count_coro
{
    struct promise_type
    {
        int* counter_ = nullptr;

        count_coro get_return_object()
        {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() noexcept
        {
            return {};
        }
        std::suspend_never final_suspend() noexcept
        {
            return {};
        }
        void return_void()
        {
            ++*counter_;
        }
        void unhandled_exception()
        {
            std::terminate();
        }
    };

    std::coroutine_handle<promise_type> h;
};

count_coro
make_count_coro(int& counter)
{
    auto c                 = []() -> count_coro { co_return; }();
    c.h.promise().counter_ = &counter;
    return c;
}

// The same, counting atomically, for a resumption on another thread.
struct atomic_count_coro
{
    struct promise_type
    {
        std::atomic<int>* n_ = nullptr;

        atomic_count_coro get_return_object()
        {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() noexcept
        {
            return {};
        }
        std::suspend_never final_suspend() noexcept
        {
            return {};
        }
        void return_void()
        {
            n_->fetch_add(1);
        }
        void unhandled_exception()
        {
            std::terminate();
        }
    };

    std::coroutine_handle<promise_type> h;
};

capy::task<capy::io_result<>>
ok_child()
{
    co_return capy::io_result<>{};
}

// Await when_all over n children, then count one completed fan-out.
capy::task<void>
fan_out(int n, int* done)
{
    std::vector<capy::task<capy::io_result<>>> tasks;
    for (int i = 0; i < n; ++i)
        tasks.push_back(ok_child());
    auto [ec] = co_await capy::when_all(std::move(tasks));
    if (!ec)
        ++*done;
}

// Two pages: the first is inaccessible, so any read before the start of
// the second faults.
class guarded_page
{
    std::size_t page_ = 0;
    char* region_     = nullptr;

public:
    guarded_page()
    {
#if defined(_WIN32)
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        page_   = info.dwPageSize;
        region_ = static_cast<char*>(VirtualAlloc(
            nullptr, 2 * page_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        DWORD old = 0;
        VirtualProtect(region_, page_, PAGE_NOACCESS, &old);
#else
        page_ = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
        void* p = mmap(
            nullptr, 2 * page_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
            -1, 0);
        if (p == MAP_FAILED)
            std::terminate();
        region_ = static_cast<char*>(p);
        mprotect(region_, page_, PROT_NONE);
#endif
    }

    ~guarded_page()
    {
#if defined(_WIN32)
        VirtualFree(region_, 0, MEM_RELEASE);
#else
        munmap(region_, 2 * page_);
#endif
    }

    guarded_page(guarded_page const&)            = delete;
    guarded_page& operator=(guarded_page const&) = delete;

    // The first byte after the guard page.
    char* start() const noexcept
    {
        return region_ + page_;
    }
};

} // namespace

struct continuation_post_test
{
    // The reproduction from corosio#12: a bare continuation at the start
    // of a page whose previous page is unmapped, posted through the
    // concrete executor.
    void testBareContinuationAfterGuardPage()
    {
        guarded_page page;
        int ran = 0;
        auto* c = new (page.start()) capy::continuation{};
        c->h    = make_count_coro(ran).h;

        io_context ioc;
        ioc.get_executor().post(*c);
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // The same through capy's type-erased executor_ref, which is how
    // when_all's launcher posts its runners.
    void testBareContinuationAfterGuardPageTypeErased()
    {
        guarded_page page;
        int ran = 0;
        auto* c = new (page.start()) capy::continuation{};
        c->h    = make_count_coro(ran).h;

        io_context ioc;
        auto ex = ioc.get_executor();
        capy::executor_ref ref(ex);
        ref.post(*c);
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // dispatch from outside run() posts, and must not read before the
    // continuation either.
    void testBareContinuationDispatchAfterGuardPage()
    {
        guarded_page page;
        int ran = 0;
        auto* c = new (page.start()) capy::continuation{};
        c->h    = make_count_coro(ran).h;

        io_context ioc;
        auto h = ioc.get_executor().dispatch(*c);
        BOOST_TEST(h == std::noop_coroutine());
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // A bare continuation whose preceding bytes equal the tag the old check
    // looked for (0xC0710A, 8 bytes before) is still a bare continuation:
    // it must be resumed, not run as a scheduler_op it is not.
    void testBareContinuationBehindTagBytes()
    {
        alignas(std::max_align_t) unsigned char storage[128] = {};
        constexpr std::size_t at = 64;
        std::uint32_t const tag  = 0xC0710Au;
        std::memcpy(storage + at - 8, &tag, sizeof(tag));
        // Fill the rest of what the old check would have read as a
        // scheduler_op with bytes that are not a valid vtable.
        std::memset(storage, 0xA5, at - 8);

        int ran = 0;
        auto* c = new (storage + at) capy::continuation{};
        c->h    = make_count_coro(ran).h;

        io_context ioc;
        ioc.get_executor().post(*c);
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // A continuation_op is still recognised, and a bare continuation is
    // not, whatever its next field holds.
    void testContinuationOpIsRecognised()
    {
        detail::continuation_op op;
        BOOST_TEST(detail::continuation_op::try_from_continuation(op.cont) == &op);

        capy::continuation bare{};
        BOOST_TEST(detail::continuation_op::try_from_continuation(bare) == nullptr);
        bare.next = &op.cont;
        BOOST_TEST(detail::continuation_op::try_from_continuation(bare) == nullptr);

        int ran = 0;
        op.cont.h = make_count_coro(ran).h;
        io_context ioc;
        ioc.get_executor().post(op.cont);
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // A continuation_op whose cont another executor queued (which
    // overwrites next) is still resumed correctly by an io_context,
    // through the fallback path.
    void testContinuationOpAfterAnotherExecutor()
    {
        detail::continuation_op op;
        std::atomic<int> pool_ran{0};
        {
            capy::thread_pool pool(1);
            auto f           = []() -> atomic_count_coro { co_return; }();
            f.h.promise().n_ = &pool_ran;
            op.cont.h        = f.h;
            pool.get_executor().post(op.cont);
            auto const deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (pool_ran.load() == 0 &&
                   std::chrono::steady_clock::now() < deadline)
                std::this_thread::yield();
        }
        BOOST_TEST_EQ(pool_ran.load(), 1);

        int ran   = 0;
        op.cont.h = make_count_coro(ran).h;
        io_context ioc;
        ioc.get_executor().post(op.cont);
        ioc.run();
        BOOST_TEST_EQ(ran, 1);
    }

    // The path the crash took: when_all over a vector of tasks posts
    // each runner's bare continuation through the io_context executor.
    void testWhenAllOverManyTasks()
    {
        io_context ioc;
        int done = 0;
        for (int round = 0; round < 64; ++round)
        {
            capy::run_async(ioc.get_executor())(fan_out(1 + round % 9, &done));
        }
        ioc.run();
        BOOST_TEST_EQ(done, 64);
    }

    void run()
    {
        testBareContinuationAfterGuardPage();
        testBareContinuationAfterGuardPageTypeErased();
        testBareContinuationDispatchAfterGuardPage();
        testBareContinuationBehindTagBytes();
        testContinuationOpIsRecognised();
        testContinuationOpAfterAnotherExecutor();
        testWhenAllOverManyTasks();
    }
};

TEST_SUITE(continuation_post_test, "boost.corosio.continuation_post");

} // namespace boost::corosio
