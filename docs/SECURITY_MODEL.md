# Security Model

This document records the current security model for Frog Lobby and the areas where additional hardening is valuable.

It is deliberately explicit about limitations. Public code is easier to review when maintainers distinguish **implemented controls** from **desired controls**.

## Security objectives

Frog Lobby aims to protect:

1. Player identity and account binding.
2. Ownership-gated access to official Frog Wars services.
3. PlayFab session/account integrity.
4. Virtual currency, inventory, cosmetics, and rewards.
5. Leaderboard integrity.
6. Multiplayer room/session integrity.
7. Server secrets and signing keys.
8. Availability of public backend endpoints.
9. Player network metadata exposed during connection coordination.

## Trust boundaries

### Untrusted

Treat the following as attacker-controlled unless verified:

- request bodies and query parameters;
- Unity client state;
- submitted PlayFab IDs;
- scores, elapsed times, rewards, placements, and item IDs;
- room/session identifiers received from clients;
- direct-connect candidate metadata;
- forwarded IP headers unless the deployment guarantees a trusted proxy chain.

### Trusted only after verification

- Frog Wars signed-session claims.
- PlayFab identities derived from authenticated session tickets.
- itch.io ownership results obtained server-side.
- server-side persisted reward/inventory state.

### Secret/server-only

- RSA private signing key;
- PlayFab secret key;
- account-link HMAC secret;
- shop administrator token;
- development bypass token.

## Implemented controls

The current codebase includes several important controls.

### Signed and expiring sessions

Frog Wars sessions are signed with RSA/SHA-256. The private key remains server-side while clients can use the corresponding public key for verification.

### Server-side ownership verification

itch.io ownership is checked by the backend rather than accepted as a client assertion.

### PlayFab authentication and account binding

Sensitive PlayFab-backed flows authenticate a session ticket and compare identities rather than trusting a submitted player ID alone.

### Server-authoritative economy operations

Inventory/currency/statistic changes are performed through backend PlayFab calls. Client requests are constrained before value is granted or spent.

### Duplicate/replay resistance

Examples include duplicate match receipts, per-request fishing IDs, persisted reward state, and checks that prevent repeatedly claiming the same purchase reward.

### Race-sensitive serialization

Selected per-player operations use keyed serialization so concurrent requests cannot freely interleave.

### Time and plausibility validation

Transient sessions expire. Arcade submissions have timing/frequency constraints and distance plausibility checks. Reward cooldowns use backend time.

### Secret comparisons

Selected high-value secret comparisons use constant-time comparison.

### Input normalization

The code bounds/sanitizes many identifiers, ports, numeric values, arrays, and reward inputs before use.

## Current hardening priorities

These are areas for continued security work and external review.

### 1. Bind every room mutation to an authorized principal or capability

Room heartbeat, deletion, candidate submission, readiness, and nomination should be consistently bound to the correct authenticated host/client or to a short-lived signed capability.

Opaque room/session IDs should not be treated as sufficient authorization by themselves.

### 2. Enforce token purpose and claim semantics centrally

Different token classes should be accepted only for their intended purpose. Validation should explicitly check expected token type/purpose, version, required claims, and expiry semantics at each boundary.

### 3. Add broad rate limiting and abuse controls

Authentication, room creation/mutation, session coordination, and other public endpoints should have deployment-appropriate request limits in addition to operation-specific checks.

### 4. Tighten proxy and origin policy

Production deployments should use explicit trusted-proxy configuration and an allowlist-based CORS policy rather than relying on permissive defaults.

Forwarded IP headers are trustworthy only when supplied/overwritten by a trusted proxy.

### 5. Minimize direct-connect metadata exposure

Direct networking can reveal public address/port metadata. Relay should be preferred when privacy or hostile-network resistance matters, and direct-connect data should be exposed only to authorized participants.

### 6. Improve authorization tests

Add negative tests proving that:

- one player cannot mutate another player's state;
- one room participant cannot control another session;
- expired/wrong-purpose tokens are rejected;
- duplicate and concurrent value-granting requests remain safe;
- administrative operations cannot be reached without valid secrets.

### 7. Add structured security telemetry

Security-sensitive rejections should be logged with privacy-preserving identifiers so abuse patterns can be investigated without unnecessarily storing raw personal/network data.

### 8. Review denial-of-service surfaces

Bound request sizes, map growth, candidate arrays, expensive password hashing attempts, outbound third-party calls, and repeated auth operations. Apply timeouts and rate limits consistently.

## Security review questions

When changing a route, ask:

1. Who is the principal?
2. How was that identity authenticated?
3. Is the resource actually owned/controlled by that principal?
4. Which request fields are merely claims?
5. Can retrying the request duplicate an effect?
6. Can two concurrent requests violate an invariant?
7. Does the server or client control time/randomness?
8. What happens when itch.io, PlayFab, relay, or geo lookup fails?
9. Is any secret or network identifier exposed in logs or responses?
10. Can the same mechanism be tested automatically?

## Desired future work

High-value future maintenance includes:

- security-focused PR review;
- fuzz/property tests for parsers and state transitions;
- authorization regression tests;
- dependency scanning;
- automated secret scanning;
- structured release/security notes;
- deeper static and semantic security analysis of networking/authentication changes.

These are particularly suitable for automated maintainer tooling because the project combines several trust boundaries in a compact codebase.
