# ALPN negotiation

Configure the ordered application protocol list on each endpoint before
constructing its TLS stream:

```cpp
tls_context client_context;
client_context.set_alpn({"h2", "http/1.1"}).value();

tls_context server_context;
server_context.set_alpn({"h2", "http/1.1"}).value();
```

The client sends its list in the ClientHello. The server selects the first
client-offered protocol that appears in its configured list. After a successful
handshake, `tls_stream::selected_alpn()` returns the protocol on both endpoints:

```cpp
(co_await stream.handshake(tls_stream::client)).value();

if (stream.selected_alpn() == "h2")
{
    // Start HTTP/2.
}
```

The returned `std::string_view` remains valid until the stream is reset or
destroyed. It is empty before the handshake, when neither endpoint configures
ALPN, or when the client and server lists do not overlap. A missing overlap does
not fail the TLS handshake.

Each protocol identifier must contain between 1 and 255 bytes. The complete
encoded list must fit in 65535 bytes.

OpenSSL provides ALPN when supported by the linked OpenSSL library. WolfSSL must
be built with `HAVE_ALPN` for negotiation support.
