// Copied from the control plane's internal/publicaddr (EXC-658); keep the two in step.

// Package publicaddr decides whether a user-supplied outbound target is one
// the platform may reach on that user's behalf.
//
// # Threat model
//
// Project members configure outbound destinations for the edge-function
// runtime (the per-project egress allowlist, EXC-348). Without a check a
// member could name 127.0.0.1, an RFC-1918 address, the cloud metadata
// endpoint or a cluster-internal service and turn a function into an SSRF
// pivot into the platform's own network. Two checks close that:
//
//   - ClassifyAddr refuses internal ranges, IPv4 and IPv6: loopback,
//     unspecified, RFC-1918, CGNAT (100.64/10), link-local (169.254/16,
//     fe80::/10), IPv6 ULA (fc00::/7), deprecated site-local (fec0::/10),
//     multicast, reserved/benchmark space, the discard prefix and cloud
//     metadata addresses (169.254.169.254, fd00:ec2::254). Encapsulated
//     IPv4 — v4-mapped (::ffff:a.b.c.d), v4-compatible (::a.b.c.d), NAT64
//     (64:ff9b::/96) and 6to4 (2002::/16) — is unwrapped and the embedded
//     IPv4 classified; Teredo (2001::/32) is refused outright.
//   - ValidateHostSyntax accepts exactly one hostname or IP literal, with no
//     port, zone id, path or multi-host list, and refuses the reserved
//     suffixes that only ever name something inside the platform network.
//
// Dialer applies ClassifyAddr at connect time: every address a name resolves
// to is checked and the checked address is the one dialled, so DNS rebinding
// between check and connect gains nothing (log drains, EXC-658).
//
// Errors never echo a resolved address back to the user.
package publicaddr
