# Unhttp
An async Rust (tokio) HTTP library that allows non-standard (ab)uses of the
protocol.

> [!NOTE]
> WIP - things may drastically change between versions

Based on httparse, http and tokio, this aims to be a HTTP client and
(eventually) server library for use cases where Hyper is difficult to wrangle.

# Why

> Another HTTP library, really?

Yes, I needed something to work where I was using Hyper and my HTTP server
wasn't exactly supported.

Unhttp is my attempt to write an easy to hack on HTTP library.
