# Third-party notices

Penteos is licensed under the GNU AGPL-3.0 (see `LICENSE`). It builds on the work of many other
projects, under their own licenses.

## Included in this repository

| Component | License | Where |
|---|---|---|
| Geist and Geist Mono fonts (Vercel) | SIL Open Font License 1.1 | `apps/desktop/electron/browser/fonts/` (license text: `OFL.txt` in the same folder) |

## Bundled into the app at build time

npm dependencies are installed from the registry and keep their own licenses. All of them are
permissive (MIT, ISC, Apache-2.0, BSD, OFL and similar). Every build writes
`THIRD_PARTY_LICENSES.txt` next to the bundled core, with the full license and notice text of each
package it ships (`node scripts/licenses.mjs` writes the same file on demand). The most visible ones:

| Component | License |
|---|---|
| Electron (and Chromium, Node.js) | MIT; Chromium's components under their own licenses, listed in the app's `LICENSES.chromium.html` |
| React, React DOM | MIT |
| OpenAI SDK | Apache-2.0 |
| Anthropic SDK | MIT |
| Model Context Protocol SDK | MIT |
| tldts (public suffix list) | MIT |
| ipaddr.js | MIT |
| Paged.js (PDF reports) | MIT |
| xterm.js | MIT |
| dockview | MIT |
| cmdk | MIT |
| Lucide icons | ISC |
| Inter, JetBrains Mono, Geist (via Fontsource) | SIL Open Font License 1.1 |
| docx | MIT |
| fflate | MIT |
| ws | MIT |
| zod | MIT |
| node-pty | MIT |

## Downloaded at run time, never redistributed

Penteos can install security tools for the operator. They are **downloaded from each project's
own release page** (or package index), checked against a fixed SHA-256 in Penteos's catalog, and
installed in the user's data folder. Penteos does not ship them; each keeps its license:

| Tool | License | Source |
|---|---|---|
| subfinder, dnsx, httpx, nuclei, katana, interactsh | MIT | github.com/projectdiscovery |
| ffuf | MIT | github.com/ffuf/ffuf |
| gobuster | Apache-2.0 | github.com/OJ/gobuster |
| uv | MIT or Apache-2.0 | github.com/astral-sh/uv |
| sqlmap | GPL-2.0 | pypi.org/project/sqlmap |
| nmap | Nmap Public Source License (NPSL) | nmap.org |

Tools already installed on the system are used as they are.
