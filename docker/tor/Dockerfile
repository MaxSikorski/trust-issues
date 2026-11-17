# A minimal Tor client for Trust Issues: SOCKS proxy only, no relay, no control port.
#
# Tor package choice: Debian bookworm's own `tor`, pinned to the exact version.
# Checked 2026-11-17: bookworm and bookworm-security both carry 0.4.9.11-0+deb12u1,
# which is the current Tor 0.4.9 series (security-updated by Debian), so the Tor
# Project's own apt repo would give nothing newer. Using Debian's archive means
# one signing key (Debian's, already in the base image) and no extra key to pin.
# If this version is superseded, apt can no longer fetch it and the build fails
# loudly; bump the pin and the base digest together.

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

LABEL org.opencontainers.image.title="Trust Issues: Tor client" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/MaxSikorski/trust-issues"

RUN apt-get update \
 && apt-get install -y --no-install-recommends tor=0.4.9.11-0+deb12u1 \
 && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc

# The package creates the unprivileged user debian-tor.
RUN install -d -o debian-tor -g debian-tor -m 0700 /var/lib/tor
USER debian-tor
VOLUME /var/lib/tor
EXPOSE 9050

# Healthy once Tor says it has fully bootstrapped (it logs to this file).
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=5 \
  CMD grep -q "Bootstrapped 100%" /var/lib/tor/notice.log

# The log is removed first so an old "Bootstrapped 100%" cannot fake a healthy start.
ENTRYPOINT ["sh", "-c", "rm -f /var/lib/tor/notice.log; exec tor -f /etc/tor/torrc"]
