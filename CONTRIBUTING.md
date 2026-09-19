# Contributing to Frog Lobby

Thanks for helping improve Frog Lobby.

The project is a security-sensitive multiplayer backend. Small changes can affect authentication, account identity, networking, rewards, or player data, so contributions should be narrow, testable, and explicit about their trust assumptions.

## Development setup

Requirements:

- Node.js 20+ recommended.
- npm.

Install dependencies:

```bash
npm install
```

Run the test suite:

```bash
npm test
```

Start the backend:

```bash
npm start
```

## Before opening a pull request

Please:

1. Keep the change focused.
2. Explain the problem and the intended behavior.
3. Add or update tests when behavior changes.
4. Run `npm test`.
5. Do not include production secrets, tokens, private keys, or player data.
6. Call out any new environment variables.
7. Call out any change to authentication, authorization, relay/direct networking, account binding, currency, inventory, rewards, or leaderboards.

## Security-sensitive changes

For changes affecting a trust boundary, describe:

- What input is untrusted?
- Which identity is authoritative?
- What prevents one player from acting as another?
- Is the operation safe to retry?
- Can concurrent requests produce duplicate effects?
- What expires, and who controls the clock?
- What server-side invariant is being enforced?
- What happens if a third-party service is unavailable?

Prefer server-authoritative validation over trusting client assertions.

## Testing guidance

Useful tests include:

- malformed and boundary-value input;
- mismatched account/session identities;
- expired or invalid sessions;
- duplicate/replayed requests;
- concurrent requests;
- unauthorized resource mutation;
- maximum/minimum reward values;
- unavailable third-party services;
- invalid room/session lifecycle transitions.

## Pull requests

A good PR description includes:

- **Problem**
- **Approach**
- **Security impact**
- **Tests**
- **Configuration/deployment impact**

Keep refactors separate from behavioral/security changes when practical.

## Reporting vulnerabilities

Do not open a public issue containing exploit details. Follow [SECURITY.md](SECURITY.md).
