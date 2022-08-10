# rust-dns-client-v2
simple rust dns client, take 2

this is a dns client/library that is functional but with limited features.

the following are places where the code needs work:
1) tests. tests tests tests tests. there's a inverse correlation in the test code between coverage of a function and its size. for smaller functions, banging out a test was almost no work. for larger functions, or functions that glued together the use of multiple smaller functions, the work becomes much larger (e.g., creating vec<u8> buffers to test with is extremely tedious, esp. when testing parsing entire dns responses).

here are some possible future features to add:
1) support for different qtypes. right now, we support 9 (10, if you want to include ANY) record types. By this I mean that there's a code structure and functions to parse from/write to bytes those records. other record types are only understood as a vec<u8>, so there's less you can do with those right now.
2) other delivery methods in the client. right now, udp only. tcp/dot/doh/odoh/doq? support in the future would be nice. or, should those be done in separate client binaries (esp doh/odoh/doq)?
3) support for ipv6 servers. right now, if you specify the -s (server) argument to point to 2001:4860:4860::8888 (google dns), we panic.
