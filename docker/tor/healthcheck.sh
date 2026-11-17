#!/bin/bash
# Healthy = Tor answers a SOCKS5 greeting now, and it logged "Bootstrapped 100%".
# The log is deleted by the entrypoint at start, so an old line can't fake it.
grep -q "Bootstrapped 100%" /var/lib/tor/notice.log || exit 1
exec 3<>/dev/tcp/127.0.0.1/9050 || exit 1
printf '\x05\x01\x00' >&3
reply=$(timeout 3 head -c2 <&3 | od -An -tx1 | tr -d ' \n')
[ "$reply" = "0500" ]
