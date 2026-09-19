# Security Policy

Security matters in Frog Lobby because the service sits between untrusted game clients and security-sensitive systems such as identity, multiplayer sessions, PlayFab data, virtual currency, inventory, and leaderboards.

## Supported code

Security fixes target the current `main` branch unless a maintained release branch is explicitly documented.

## Reporting a vulnerability

Please do **not** disclose a suspected vulnerability, exploit, credential, private key, account token, or reproduction containing sensitive player data in a public issue.

Preferred process:

1. Use **GitHub Private Vulnerability Reporting / Security Advisories** for this repository when available.
2. Include the affected component, impact, reproduction steps, and the smallest safe proof of concept needed to understand the issue.
3. Remove secrets, personal data, access tokens, session tickets, and real player identifiers from the report.
4. Allow reasonable time for triage and a fix before public disclosure.

If private vulnerability reporting is temporarily unavailable, open a normal issue containing **no exploit details** and request a private reporting channel.

## High-priority security areas

Reports are especially useful when they involve:

- Authentication or session-token validation.
- Token purpose, lifetime, signing, or identity binding.
- itch.io ownership verification.
- PlayFab session/account binding.
- Unauthorized room/session mutation.
- Relay/direct-connect authorization or connection metadata.
- Replay, duplicate-request, or race-condition behavior.
- Virtual currency, inventory, rewards, or shop authorization.
- Leaderboard/score validation.
- Administrative endpoints or secret handling.
- Input validation, denial of service, or unsafe proxy/origin assumptions.

## Secrets

Never commit:

- `PLAYFAB_SECRET_KEY`
- `FROGWARS_SESSION_PRIVATE_KEY`
- `ACCOUNT_LINK_HMAC_SECRET`
- `SHOP_ADMIN_TOKEN`
- `ITCH_DEV_BYPASS_TOKEN`
- OAuth access tokens
- PlayFab session tickets
- production credentials of any other kind

If a production secret is accidentally committed, treat it as compromised and rotate/revoke it. Removing it from the latest commit is not sufficient.

## Security posture

The repository contains meaningful security controls, but it is under active development. Public source code and a security policy are intended to make review easier; they are not a guarantee that the software is vulnerability-free.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the current trust model and hardening priorities.
