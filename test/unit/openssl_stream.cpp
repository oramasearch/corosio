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

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

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

    /** Set an environment variable for one scope, then restore it. */
    struct scoped_env
    {
        std::string name_;
        std::optional<std::string> saved_;

        scoped_env(char const* name, std::string const& value) : name_(name)
        {
            if (auto const* old = std::getenv(name))
                saved_ = old;
            set(value.c_str());
        }

        ~scoped_env()
        {
            if (saved_)
                set(saved_->c_str());
            else
                unset();
        }

        void set(char const* value)
        {
#ifdef _WIN32
            _putenv_s(name_.c_str(), value);
#else
            ::setenv(name_.c_str(), value, 1);
#endif
        }

        void unset()
        {
#ifdef _WIN32
            _putenv_s(name_.c_str(), "");
#else
            ::unsetenv(name_.c_str());
#endif
        }
    };

    static std::filesystem::path make_temp_dir(char const* label)
    {
        auto dir = std::filesystem::temp_directory_path() /
            (std::string("corosio-") + label + "-" +
             std::to_string(
                 std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        return dir;
    }

    static void write_file(std::filesystem::path const& path, char const* text)
    {
        std::ofstream out(path, std::ios::binary);
        out << text;
    }

    /** set_default_verify_paths() must load the platform trust store.

        OpenSSL's default store honors SSL_CERT_FILE, so pointing it at the
        test CA makes the "system" roots trust the test server. Before the
        fix the flag was recorded and never applied, the client trusted
        nothing, and this handshake failed.
    */
    void testDefaultVerifyPaths()
    {
        using namespace test;

        auto dir = make_temp_dir("default-verify");
        auto ca_file = dir / "ca.pem";
        write_file(ca_file, ca_cert_pem);

        {
            scoped_env env("SSL_CERT_FILE", ca_file.string());

            io_context ioc;
            tls_context client_ctx;
            BOOST_TEST(!client_ctx.set_default_verify_paths());
            BOOST_TEST(!client_ctx.set_verify_mode(tls_verify_mode::peer));
            auto server_ctx = make_server_context();
            run_tls_test(ioc, client_ctx, server_ctx, make_stream, make_stream);
        }

        std::filesystem::remove_all(dir);
    }

    /** add_verify_path() must load a hashed certificate directory. */
    void testAddVerifyPath()
    {
        using namespace test;

        auto dir = make_temp_dir("verify-path");

        BIO* bio = BIO_new_mem_buf(ca_cert_pem, -1);
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        BOOST_TEST(cert != nullptr);
        if (!cert)
            return;
        char name[32];
        std::snprintf(
            name, sizeof(name), "%08lx.0", X509_subject_name_hash(cert));
        X509_free(cert);
        write_file(dir / name, ca_cert_pem);

        {
            io_context ioc;
            tls_context client_ctx;
            BOOST_TEST(!client_ctx.add_verify_path(dir.string()));
            BOOST_TEST(!client_ctx.set_verify_mode(tls_verify_mode::peer));
            auto server_ctx = make_server_context();
            run_tls_test(ioc, client_ctx, server_ctx, make_stream, make_stream);
        }

        std::filesystem::remove_all(dir);
    }

    /** A CA bundle trusts every certificate in it, not only the first.

        load_verify_file() of a system bundle such as /etc/ssl/cert.pem
        passes one string holding many certificates. Only the first was
        added, so a server signed by any later root failed verification.
    */
    void testCertificateAuthorityBundle()
    {
        using namespace test;

        std::string bundle = std::string(root_ca_cert_pem) + ca_cert_pem;

        // In memory
        {
            io_context ioc;
            tls_context client_ctx;
            BOOST_TEST(!client_ctx.add_certificate_authority(bundle));
            BOOST_TEST(!client_ctx.set_verify_mode(tls_verify_mode::peer));
            auto server_ctx = make_server_context();
            run_tls_test(ioc, client_ctx, server_ctx, make_stream, make_stream);
        }

        // From a file
        {
            auto dir = make_temp_dir("ca-bundle");
            auto file = dir / "bundle.pem";
            write_file(file, bundle.c_str());

            io_context ioc;
            tls_context client_ctx;
            BOOST_TEST(!client_ctx.load_verify_file(file.string()));
            BOOST_TEST(!client_ctx.set_verify_mode(tls_verify_mode::peer));
            auto server_ctx = make_server_context();
            run_tls_test(ioc, client_ctx, server_ctx, make_stream, make_stream);

            std::filesystem::remove_all(dir);
        }
    }

    /** A failed verification says why, instead of an opaque number.

        OpenSSL's packed error codes used to be returned in
        std::system_category(), which libc++ renders as "unspecified
        system_category error" (corosio's private fork, liquid#368).
    */
    void testVerifyFailureMessage()
    {
        using namespace test;

        io_context ioc;
        tls_context client_ctx; // trusts nothing
        BOOST_TEST(!client_ctx.set_verify_mode(tls_verify_mode::peer));
        auto server_ctx = make_server_context();

        auto [s1, s2] = corosio::test::make_socket_pair(ioc);
        auto client = make_stream(s1, client_ctx);
        auto server = make_stream(s2, server_ctx);

        std::error_code client_ec;
        auto client_task = [&]() -> capy::task<> {
            auto [ec] = co_await client.handshake(openssl_stream::client);
            client_ec = ec;
            s1.cancel();
            s1.close();
            s2.cancel();
            s2.close();
        };
        auto server_task = [&]() -> capy::task<> {
            auto [ec] = co_await server.handshake(openssl_stream::server);
            (void)ec;
        };
        capy::run_async(ioc.get_executor())(client_task());
        capy::run_async(ioc.get_executor())(server_task());
        ioc.run();

        BOOST_TEST(static_cast<bool>(client_ec));
        BOOST_TEST(
            std::string_view(client_ec.category().name()) ==
            "openssl.x509_verify");
        auto const message = client_ec.message();
        BOOST_TEST(message.starts_with("certificate verify failed: "));
        BOOST_TEST(message.find("unspecified") == std::string::npos);
        BOOST_TEST(message.find("Unknown error") == std::string::npos);
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
        test::testPeerCertificate(make_stream);

        test::testReset(make_stream, cert_modes);
        test::testResetViaHandshake(make_stream, cert_modes);
        test::testResetFuse(make_stream);

        testCertificateChain();
        testFullDuplex();
        testDefaultVerifyPaths();
        testAddVerifyPath();
        testCertificateAuthorityBundle();
        testVerifyFailureMessage();
        testName();
        testNextLayer();
    }
};

TEST_SUITE(openssl_stream_test, "boost.corosio.openssl_stream");

} // namespace boost::corosio

#endif
