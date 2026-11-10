# Security policy

Penteos is a tool for security testing, so its own security matters twice: a flaw in Penteos can
expose the operator's machine and their clients' data.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Include:

- what the problem is and where (component, file, operation);
- how to reproduce it, as precisely as you can;
- what an attacker could achieve, and any conditions it needs;
- the version or commit you tested.

You will get an acknowledgement within **5 working days**. We will keep you informed while we
work on a fix, and credit you in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes while the project is in its 0.x series.

## Scope

In scope: Penteos itself - the desktop app, the core, the team server, the MCP bridge, the plugin
runtime and sandbox, the intercepting proxy, the update and tool-installation paths, and anything
that could let a target, a plugin or an AI agent act outside the scope and approvals the operator
set.

Out of scope: vulnerabilities in the third-party tools Penteos can run (report those upstream),
and findings about systems you are testing *with* Penteos.

## Known limits

What Penteos does not protect against today, so you can decide with the facts:

- **Masking client data before the model** recognises what it can name: values by their field,
  table or form label; values with a format (e-mails, cards, national IDs with check digits, IBAN,
  tokens and keys); clinical notes and birth dates by their context; and any value already masked
  once, wherever it appears again. `pnpm privacy:measure` shows the result on synthetic data. A value
  with no format and no context, in free prose, the first time it appears (a name in a sentence
  nobody labelled), still reaches the model. With a model running on your machine nothing leaves it,
  so nothing is masked.
- **Provider API keys** are sealed on disk with a key kept in the same data folder (owner-only),
  not in the operating system's keychain. Anyone who can read your user's files can read them.
- **Exported projects** (`.penteos`) carry the captured traffic, session cookies and the client's
  data; only stored secrets are left out. Keep them as you keep the engagement.
- **Plugins** run with the freedom the operator grants when approving them. A plugin approved to
  run free is ordinary code on your machine; choose "isolated" for code you have not read.
- **Codex** runs with a read-only sandbox: it cannot write or reach the network by itself, but it can
  read files your user can read, and what it reads could reach a target through Penteos's tools.
  Claude Code runs with its own tools switched off.
- **The agent's browser** listens for its controller on a random local port; any process of your
  user on the same machine could drive it while it is open.
- **The team server is experimental.** On the network it requires TLS (or an explicit
  `--allow-plaintext` behind a VPN or SSH tunnel).

## Safe harbor

We will not pursue anyone who reports in good faith, avoids harming users and their data, and
gives us reasonable time to fix the problem before disclosing it.
