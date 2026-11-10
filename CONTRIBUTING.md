# Contributing to Penteos

Thank you for helping. Penteos is a security tool used on real engagements, so we value changes
that are correct, tested and easy to review over changes that are big.

## Before you start

- **Bugs:** open an issue with steps to reproduce (the template asks for what we need).
- **Security problems:** never in a public issue - see [SECURITY.md](SECURITY.md).
- **Larger changes or new features:** open a discussion or an issue first, so we can agree on the
  approach before you invest time in it.

## Setting up

You need Linux, [pnpm](https://pnpm.io) 10 and a C++ toolchain (`build-essential` or your
distribution's equivalent) for `node-pty`, the integrated terminal. pnpm downloads and uses the
Node.js version pinned in `.npmrc` (24.x) for this project, without touching your system's Node.

```sh
pnpm install
pnpm dev          # the desktop app, with the core running inside it
```

`pnpm dev -- --desktop-entry` also adds a menu entry for the development copy, so your dock shows
Penteos's icon. On Ubuntu 24.04 and later, the first `pnpm dev` from a plain terminal asks for
your password once, to let Electron use Chromium's sandbox (an AppArmor profile for that exact
binary).

Data lives in `~/.local/share/penteos` (or `$XDG_DATA_HOME/penteos`); set `PENTEOS_DATA_DIR` to
work on a throwaway folder.

## Repository layout

```
apps/desktop/          Electron + React workbench
packages/schema/       The graph schema, the ingest format and natural keys
packages/core/         The headless core: engagements, scope, ingest, audit, tools, plugins,
                       proxy, reports and the operation catalog
packages/server/       The core process: operations over HTTP/WebSocket, agents, terminal, MCP
packages/plugin-sdk/   What plugin authors build against
packages/parsers/      Tool output parsers (nmap, BloodHound)
scripts/               Development, release and test tooling
```

Every action - from the interface, an AI agent or an MCP client - is an **operation** in the
core's catalog (`packages/core/src/ops/catalog/`). Add new capabilities there, with an input
schema, the actors allowed to call it, and a clear description: AI agents read it.

## Checks

```sh
pnpm typecheck    # every package
pnpm test         # every test suite
pnpm i18n:check   # interface text: both catalogs, no hardcoded strings
pnpm electron:check  # the desktop main process loads (catches start-up errors)
pnpm ui:smoke     # opens every section of the interface in headless Chrome and screenshots it
```

CI runs all of them on every pull request except `ui:smoke`, which needs Google Chrome (or
`CHROME=/path/to/chromium`): run it yourself when you touch the interface.

## Guidelines

- **Scope is law.** Anything that can touch a target must go through the core's scope checks and
  approvals, like every existing tool. If in doubt, ask.
- **Code and comments in English.** Comments explain *why*, not what the code already says.
- **Interface text** goes in the catalogs, `apps/desktop/src/i18n/es` and `en`, never in the
  components. Spanish uses a neutral register (formal "usted", no regional forms); the checker
  enforces it.
- **Tests** come with the change: a bug fix with the test that would have caught it, a feature
  with tests of its behaviour. Never add a test that touches the real system (no `sudo`,
  `pkexec`, package managers or network targets outside `127.0.0.1`).
- **Small, focused pull requests** are reviewed faster.

## Sign-off

Contributions are accepted under the project's license, the GNU AGPL-3.0. Sign off every commit
to certify that you wrote it or have the right to submit it, as described in the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "Explain what changes and why"
```

## Plugins

Most new integrations do not need a change to Penteos: they can be plugins. See
`packages/plugin-sdk` and the plugins that ship with Penteos in `packages/core/catalog`.
