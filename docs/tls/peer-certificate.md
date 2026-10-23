# Peer certificate

After a successful handshake, `tls_stream::peer_certificate_der()` returns the
DER encoding of the leaf certificate the peer presented:

```cpp
(co_await stream.handshake(tls_stream::server)).value();

std::vector<unsigned char> der = stream.peer_certificate_der();
```

The vector is a copy, so it stays valid after the stream is reset or destroyed.
It is empty:

- before a handshake, and after `reset()`;
- when the peer presented no certificate (a client, when the server context does
  not request one).

The certificate has passed the context's verification only when the verify mode
required one (`tls_verify_mode::peer` or `require_peer`). With
`tls_verify_mode::none` the bytes are whatever the peer sent.

The intended use is binding an identity a peer states inside the application
protocol (a node id, a user name) to the identity its certificate proves, after
mutual TLS has verified the chain.

OpenSSL returns the certificate from `SSL_get1_peer_certificate`. WolfSSL must
be built with `SESSION_CERTS` (included in `--enable-all`); without it the
accessor returns an empty vector.
