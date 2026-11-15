# A connect started after its socket was registered

Applies to the reactor backends (epoll, kqueue, select). Fork change for
oramasearch/corosio#10, found by a downstream application.

## The problem

`tcp_socket::connect()` opens the socket, which registers it with the reactor,
when the awaitable is created. The connect itself starts later, in
`await_suspend`. A socket opened with `open()` and connected later has the same
gap. During it, a reactor pass can poll the socket.

On Linux, epoll reports a TCP socket that is open but not yet connecting as
`EPOLLOUT|EPOLLHUP`. A probe on kernel 6.8:

```
open, registered, no connect:      events=OUT HUP
connect() = -1 (Operation now in progress)
SO_ERROR after connect = 0
after connect:                     events=OUT
```

The epoll backend maps `EPOLLHUP` to read, write and error, so that a hangup reaches a
parked op, and the
descriptor state recorded it. Two orders followed:

- **Pass, then connect, then the descriptor runs.** The connect parks in
  `connect_op`, then `invoke_deferred_io()` runs with the stale error bit.
  `SO_ERROR` is 0, so it substituted `EIO` and failed the connect. Every connect
  started this way failed, which is what the application saw.
- **Pass, the descriptor runs, then connect.** No op is parked, so the event
  sets `write_ready`. `register_op()` then ran the connect op's `perform_io()`
  at once, and `SO_ERROR == 0` could complete the connect as a success before the
  handshake finished.

macOS kqueue reports no such event for an unconnected socket, so the bug did not
show there.

## The fix

A readiness event is no longer taken as proof that a connect finished.

- `reactor_connect_op::perform_io()` reads `SO_ERROR` and, when it is 0, calls
  `getpeername()`. `ENOTCONN` means the socket is still connecting: the op
  completes with `EAGAIN`, so it stays parked (in `register_op()` and in
  `invoke_deferred_io()`) until the next edge. Any other `getpeername()` error
  fails the connect with that error.
- `invoke_deferred_io()` still substitutes `EIO` for an error event with
  `SO_ERROR == 0`, and still fails parked reads and writes with it, so a hangup
  surfaces. A parked connect is the exception: it runs
  `perform_io()` instead, which re-reads `SO_ERROR` and checks the connection,
  and is re-armed if the socket is still connecting.

A real failure still carries its error. `ECONNREFUSED` and the like arrive in
`SO_ERROR` and are reported unchanged.

Opening the socket in `await_suspend` instead was not enough on its own: a socket
opened explicitly (to set options or bind) and connected later has the same gap.

## Tests

`test/unit/connect_after_open.cpp` (`boost.corosio.connect_after_open`, every
backend):

- the awaitable is created, the coroutine posts itself 0 to 4 times, then the
  connect starts; it must succeed and carry a byte both ways;
- the socket is opened, a 50 ms timer runs, then the connect starts;
- the same post sweep against a closed port must report `connection_refused`.

On Linux the one-post case puts the reactor pass between the open and the
connect, with the descriptor run after the connect parks. Without the fix it
failed with `Input/output error` on epoll on every run. The tests must run on Linux
to exercise the epoll backend.
