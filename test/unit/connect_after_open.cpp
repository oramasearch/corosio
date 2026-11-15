//
// Copyright (c) 2026 Orama Search Inc.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// A connect started some time after its socket was opened and registered
// with the reactor (oramasearch/corosio#10).
//
// tcp_socket::connect() opens the socket when the awaitable is created.
// On Linux, epoll reports a TCP socket that is open but not yet connecting
// as EPOLLOUT|EPOLLHUP. If a reactor pass records that event before the
// connect starts, and the descriptor runs after the connect is parked,
// the connect used to complete with EIO (SO_ERROR is 0, and a hangup with
// no error was turned into EIO). These tests start the connect after a
// timer delay and after 0..N posts of the coroutine, which places the
// reactor pass at every position between the open and the connect, and
// require the connect to succeed and the stream to carry data.

#include <boost/corosio/io_context.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timer.hpp>

#include <boost/capy/continuation.hpp>
#include <boost/capy/ex/io_env.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

#include <chrono>
#include <cstdio>
#include <coroutine>
#include <string_view>
#include <system_error>

#include "context.hpp"
#include "test_suite.hpp"

namespace boost::corosio {

namespace {

/* Resume the awaiting coroutine through a post to its executor, so that
   whatever is already queued (including the reactor sentinel) runs first. */
struct post_self
{
    capy::continuation c_{};

    bool await_ready() const noexcept
    {
        return false;
    }

    void await_suspend(std::coroutine_handle<> h, capy::io_env const* env)
    {
        c_.h = h;
        env->executor.post(c_);
    }

    void await_resume() const noexcept {}
};

} // namespace

template<auto Backend>
struct connect_after_open_test
{
    static std::uint16_t open_listener(tcp_acceptor& acc)
    {
        acc.open();
        acc.set_option(socket_option::reuse_address(true));
        auto ec = acc.bind(endpoint(ipv4_address::loopback(), 0));
        BOOST_TEST(!ec);
        ec = acc.listen();
        BOOST_TEST(!ec);
        return acc.local_endpoint().port();
    }

    /* The connect must succeed and carry a byte both ways. A hang is
       bounded by run_for() and reported as timed_out. */
    static void
    report(char const* what, int posts, std::error_code ec, bool done)
    {
        BOOST_TEST(!ec);
        BOOST_TEST(done);
        if (ec || !done)
            std::fprintf(
                stderr, "%s(%d): connect=%s, round trip %s\n", what, posts,
                ec.message().c_str(), done ? "done" : "not done");
    }

    /* Accept one connection and echo one byte back. */
    static capy::task<> accept_and_echo(tcp_acceptor& acc, tcp_socket& server)
    {
        auto [aec] = co_await acc.accept(server);
        BOOST_TEST(!aec);
        if (aec)
            co_return;
        char c = 0;
        auto [rec, rn] = co_await server.read_some(capy::mutable_buffer(&c, 1));
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(rn, 1u);
        auto [wec, wn] = co_await server.write_some(capy::const_buffer(&c, 1));
        BOOST_TEST(!wec);
        BOOST_TEST_EQ(wn, 1u);
    }

    /* Prove the connect really established the stream. */
    static capy::task<> round_trip(tcp_socket& client)
    {
        char out = 'x';
        auto [wec, wn] = co_await client.write_some(capy::const_buffer(&out, 1));
        BOOST_TEST(!wec);
        BOOST_TEST_EQ(wn, 1u);
        char in = 0;
        auto [rec, rn] = co_await client.read_some(capy::mutable_buffer(&in, 1));
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(rn, 1u);
        BOOST_TEST_EQ(in, 'x');
    }

    /* The awaitable is created (which opens and registers the socket),
       then the coroutine posts itself `posts` times, then the connect
       starts. */
    void connectAfterPosts(int posts)
    {
        io_context ioc(Backend);
        tcp_acceptor acc(ioc);
        auto port = open_listener(acc);
        tcp_socket client(ioc);
        tcp_socket server(ioc);
        std::error_code conn_ec = make_error_code(std::errc::timed_out);
        bool done = false;

        auto client_task = [&]() -> capy::task<> {
            auto aw = client.connect(endpoint(ipv4_address::loopback(), port));
            BOOST_TEST(client.is_open());
            for (int i = 0; i < posts; ++i)
                co_await post_self{};
            auto [ec] = co_await std::move(aw);
            conn_ec = ec;
            if (ec)
                co_return;
            BOOST_TEST_EQ(client.remote_endpoint().port(), port);
            co_await round_trip(client);
            done = true;
        };

        capy::run_async(ioc.get_executor())(accept_and_echo(acc, server));
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run_for(std::chrono::seconds(10));
        report("connectAfterPosts", posts, conn_ec, done);

        client.close();
        server.close();
        acc.close();
    }

    /* The socket is opened explicitly, the reactor polls it for a while,
       then the connect starts. */
    void connectAfterDelay()
    {
        io_context ioc(Backend);
        tcp_acceptor acc(ioc);
        auto port = open_listener(acc);
        tcp_socket client(ioc);
        tcp_socket server(ioc);
        timer t(ioc);
        std::error_code conn_ec = make_error_code(std::errc::timed_out);
        bool done = false;

        client.open();

        auto client_task = [&]() -> capy::task<> {
            t.expires_after(std::chrono::milliseconds(50));
            auto [tec] = co_await t.wait();
            BOOST_TEST(!tec);
            auto [ec] =
                co_await client.connect(endpoint(ipv4_address::loopback(), port));
            conn_ec = ec;
            if (ec)
                co_return;
            co_await round_trip(client);
            done = true;
        };

        capy::run_async(ioc.get_executor())(accept_and_echo(acc, server));
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run_for(std::chrono::seconds(10));
        report("connectAfterDelay", 0, conn_ec, done);

        client.close();
        server.close();
        acc.close();
    }

    /* A connect to a closed port started after the reactor has seen the
       open socket still reports connection_refused, not success and
       not EIO. */
    void refusedAfterPosts(int posts)
    {
        io_context ioc(Backend);
        std::uint16_t port = 0;
        {
            tcp_acceptor probe(ioc);
            port = open_listener(probe);
            probe.close();
        }
        tcp_socket client(ioc);
        std::error_code result = make_error_code(std::errc::timed_out);

        auto client_task = [&]() -> capy::task<> {
            auto aw = client.connect(endpoint(ipv4_address::loopback(), port));
            for (int i = 0; i < posts; ++i)
                co_await post_self{};
            auto [ec] = co_await std::move(aw);
            result = ec;
        };

        capy::run_async(ioc.get_executor())(client_task());
        ioc.run_for(std::chrono::seconds(10));
        if (!BOOST_TEST(result == std::errc::connection_refused))
            std::fprintf(
                stderr, "refusedAfterPosts(%d): %s\n", posts,
                result.message().c_str());

        client.close();
    }

    void run()
    {
        for (int posts = 0; posts <= 4; ++posts)
            connectAfterPosts(posts);
        connectAfterDelay();
        for (int posts = 0; posts <= 4; ++posts)
            refusedAfterPosts(posts);
    }
};

COROSIO_BACKEND_TESTS(connect_after_open_test, "boost.corosio.connect_after_open")

} // namespace boost::corosio
