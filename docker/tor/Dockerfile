# A minimal Tor client for Trust Issues: SOCKS proxy only, no relay, no control port.
#
# Tor package choice: Debian bookworm's own `tor`, pinned to the exact version.
# Checked 2026-11-17: bookworm and bookworm-security both carry 0.4.9.11-0+deb12u1,
# which is the current Tor 0.4.9 series (security-updated by Debian), so the Tor
# Project's own apt repo would give nothing newer. Using Debian's archive means
# one signing key (Debian's, already in the base image) and no extra key to pin.
# If this version is superseded, apt can no longer fetch it and the build fails
# loudly; bump the pin, the snapshot timestamp and the base digest together.

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

LABEL org.opencontainers.image.title="Trust Issues: Tor client" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/MaxSikorski/trust-issues"

# Debian packages come from a dated snapshot, not the live archive, so a
# rebuild gets the same bytes. To bump: change SNAPSHOT (a timestamp from
# https://snapshot.debian.org/archive/debian/) and the base image digest
# together, and re-check the pinned versions still exist at that timestamp.
ARG SNAPSHOT=20261117T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    "deb http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm main" \
    "deb http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm-updates main" \
    "deb http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bookworm-security main" \
    > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

RUN apt-get update \
 && apt-get install -y --no-install-recommends tor=0.4.9.11-0+deb12u1 \
 && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc
COPY healthcheck.sh /usr/local/bin/healthcheck.sh

# The package creates the unprivileged user debian-tor.
RUN install -d -o debian-tor -g debian-tor -m 0700 /var/lib/tor
USER debian-tor
VOLUME /var/lib/tor
EXPOSE 9050

# Healthy only if Tor really answers a SOCKS5 greeting right now AND its own
# log (cleared at start, below) says it bootstrapped. See healthcheck.sh.
HEALTHCHECK --interval=15s --timeout=8s --start-period=120s --retries=5 \
  CMD ["bash", "/usr/local/bin/healthcheck.sh"]

# The log is removed first so an old "Bootstrapped 100%" cannot fake a healthy start.
ENTRYPOINT ["sh", "-c", "rm -f /var/lib/tor/notice.log; exec tor -f /etc/tor/torrc"]
