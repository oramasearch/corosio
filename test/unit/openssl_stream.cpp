//
// Copyright (c) 2025 Vinnie Falco (vinnie.falco@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// Test that header file is self-contained.
#include <boost/corosio/openssl_stream.hpp>

#include "tls_stream_tests.hpp"

#include <boost/capy/read.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/timer.hpp>

#include <chrono>
#include <string>

#ifdef BOOST_COROSIO_HAS_OPENSSL

namespace boost::corosio {

// Callable wrapper for passing to test helper templates
struct openssl_stream_factory
{
    auto operator()(tcp_socket& s, tls_context const& ctx) const
    {
        return openssl_stream(&s, ctx);
    }

    auto operator()(corosio::test::mocket& s, tls_context const& ctx) const
    {
        return openssl_stream(&s, ctx);
    }
};

struct openssl_stream_test
{
    static constexpr openssl_stream_factory make_stream{};

    // Context modes supported by OpenSSL (includes anon ciphers)
    static constexpr std::array<test::context_mode, 3> all_modes = {
        test::context_mode::anon, test::context_mode::shared_cert,
        test::context_mode::separate_cert};

    static constexpr std::array<test::context_mode, 2> cert_modes = {
        test::context_mode::shared_cert, test::context_mode::separate_cert};

    void testName()
    {
        using namespace test;

        io_context ioc;
        auto ctx = make_anon_context();
        tcp_socket sock(ioc);
        openssl_stream stream(&sock, ctx);

        BOOST_TEST(stream.name() == "openssl");
    }

    /** Exercise next_layer() accessors (const and non-const). */
    void testNextLayer()
    {
        using namespace test;

        io_context ioc;
        auto ctx = make_anon_context();
        tcp_socket sock(ioc);
        openssl_stream stream(&sock, ctx);

        // Non-const overload via mutable stream.
        capy::any_stream& mutable_next = stream.next_layer();
        (void)mutable_next;

        // Const overload via reference to const.
        openssl_stream const& cref = stream;
        capy::any_stream const& const_next = cref.next_layer();
        (void)const_next;

        BOOST_TEST(&mutable_next == &const_next);
    }

    /** Test certificate chain validation (OpenSSL-specific).

        OpenSSL supports sending full certificate chains via
        use_certificate_chain() and add_extra_chain_cert().
    */
    void testCertificateChain()
    {
        using namespace test;

        // Server sends full chain
        {
            io_context ioc;
            auto client_ctx = make_rootonly_client_context();
            auto server_ctx = make_fullchain_server_context();
            run_tls_test(ioc, client_ctx, server_ctx, make_stream, make_stream);
        }

        // Server sends only entity cert (fails)
        {
            io_context ioc;
            auto client_ctx = make_rootonly_client_context();
            auto server_ctx = make_chain_server_context();
            run_tls_test_fail(
                ioc, client_ctx, server_ctx, make_stream, make_stream);
        }
    }

    /** Test that a read and a write outstanding at once both progress.

        Each side runs one writer and one reader concurrently, the
        pattern openssl_stream documents. Both writers send far more than
        the socket buffers hold, and both readers start before any data
        has arrived. Neither write can finish until the peer reads, so a
        stream that lets a pending read hold back its write (or a pending
        write hold back its read) delivers nothing. A watchdog closes the
        sockets at the deadline so a stall fails instead of hanging.
    */
    void testFullDuplex()
    {
        using namespace test;

        constexpr std::size_t payload_bytes = 32 * 1024 * 1024;

        io_context ioc;
        auto [client_socket, server_socket] = make_socket_pair(ioc);
        auto client_ctx = make_client_context();
        auto server_ctx = make_server_context();
        auto client = make_stream(client_socket, client_ctx);
        auto server = make_stream(server_socket, server_ctx);

        std::error_code client_handshake, server_handshake;
        auto hsc = [&]() -> capy::task<> {
            auto [ec] = co_await client.handshake(tls_stream::client);
            client_handshake = ec;
        };
        auto hss = [&]() -> capy::task<> {
            auto [ec] = co_await server.handshake(tls_stream::server);
            server_handshake = ec;
        };
        capy::run_async(ioc.get_executor())(hsc());
        capy::run_async(ioc.get_executor())(hss());
        ioc.run();
        ioc.restart();
        BOOST_TEST(!client_handshake);
        BOOST_TEST(!server_handshake);
        if (client_handshake || server_handshake)
            return;

        std::string const client_payload(payload_bytes, 'c');
        std::string const server_payload(payload_bytes, 's');
        std::string client_received(payload_bytes, '\0');
        std::string server_received(payload_bytes, '\0');
        std::size_t client_read = 0, server_read = 0;
        std::size_t client_written = 0, server_written = 0;
        int finished = 0;

        auto writer = [&](openssl_stream& stream, std::string const& payload,
                          std::size_t& written) -> capy::task<> {
            auto [ec, n] = co_await capy::write(
                stream, capy::const_buffer(payload.data(), payload.size()));
            written = n;
            ++finished;
        };
        auto reader = [&](openssl_stream& stream, std::string& into,
                          std::size_t& read) -> capy::task<> {
            auto [ec, n] = co_await capy::read(
                stream, capy::mutable_buffer(into.data(), into.size()));
            read = n;
            ++finished;
        };
        auto watchdog = [&]() -> capy::task<> {
            timer deadline(ioc);
            auto const started = std::chrono::steady_clock::now();
            while (finished < 4 &&
                   std::chrono::steady_clock::now() - started <
                       std::chrono::seconds(30))
            {
                deadline.expires_after(std::chrono::milliseconds(20));
                (void)co_await deadline.wait();
            }
            client_socket.close();
            server_socket.close();
        };

        capy::run_async(ioc.get_executor())(
            reader(client, client_received, client_read));
        capy::run_async(ioc.get_executor())(
            reader(server, server_received, server_read));
        capy::run_async(ioc.get_executor())(
            writer(client, client_payload, client_written));
        capy::run_async(ioc.get_executor())(
            writer(server, server_payload, server_written));
        capy::run_async(ioc.get_executor())(watchdog());
        ioc.run();

        BOOST_TEST_EQ(client_written, payload_bytes);
        BOOST_TEST_EQ(server_written, payload_bytes);
        BOOST_TEST_EQ(client_read, payload_bytes);
        BOOST_TEST_EQ(server_read, payload_bytes);
        BOOST_TEST(client_received == server_payload);
        BOOST_TEST(server_received == client_payload);
    }

    void run()
    {
        test::testHandshakeFuse(make_stream);
        test::testReadWriteFuse(make_stream);
        test::testShutdownFuse(make_stream);
        test::testSuccessCases(make_stream, all_modes);
        test::testFailureCases(make_stream);
        test::testTlsShutdown(make_stream, cert_modes);
        test::testStreamTruncated(make_stream, cert_modes);
        test::testStopTokenCancellation(make_stream);
        test::testSocketErrorPropagation(make_stream);
        test::testCertificateValidation(make_stream);
        test::testSni(make_stream);
        test::testSniCallback(make_stream);
        test::testMtls(make_stream);
        test::testAlpn(make_stream);

        test::testReset(make_stream, cert_modes);
        test::testResetViaHandshake(make_stream, cert_modes);
        test::testResetFuse(make_stream);

        testCertificateChain();
        testFullDuplex();
        testName();
        testNextLayer();
    }
};

TEST_SUITE(openssl_stream_test, "boost.corosio.openssl_stream");

} // namespace boost::corosio

#endif
