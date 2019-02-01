# Rusty NAT64

This project implements a host mapped NAT64, that is to say it only keeps
mappings between IPv6 clients and the assigned IPv4 address for that host.

*Note*: This project DOES NOT implement
[RFC 6146](https://tools.ietf.org/html/rfc6146) because we do not want to make a
middlebox which has unnecessary state, we just want to make a lightweight
transition mechanism so that IPv6 only end host networks can be deployed. As
such we accept the tradeoff to have one IPv4 address per IPv6 host to gain the
benefit of not needing to implement all the functionality described in RFC6146.
Moreover, this design allows port numbers to be the same on both sides of the
NAT64, and allows a host to use all 2^16 ports.
