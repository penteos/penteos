/**
 * Manifests shipped with Penteos. They use exactly the same format an agent or a user can write,
 * which keeps the format honest: if an integration cannot be expressed as a manifest, the format
 * is what needs fixing.
 */

const PD_IDENTITY = { args: ["-version"], pattern: "Current Version: v?[\\d.]+" };

export const BUILTIN_MANIFESTS: unknown[] = [
  {
    name: "nmap",
    description: "Port and service scanner (integrated parser for its XML output)",
    binaries: ["nmap"],
    identity: { args: ["--version"], pattern: "Nmap version [\\d.]+" },
    risk: "active",
    attack: ["T1046"],
    targets: { flags: [], positional: true, fileFlags: ["-iL"] },
    valueFlags: [],
    install: { method: "system", packages: { apt: "nmap", pacman: "nmap", dnf: "nmap", zypper: "nmap", brew: "nmap" } },
  },
  {
    name: "subfinder",
    description: "Passive subdomain discovery from public sources",
    binaries: ["subfinder", "~/go/bin/subfinder"],
    identity: PD_IDENTITY,
    risk: "passive",
    attack: ["T1596"],
    targets: { flags: ["-d", "-domain"], positional: false, fileFlags: ["-dL", "-list"], form: "host" },
    valueFlags: ["-s", "-sources", "-es", "-exclude-sources", "-t", "-timeout", "-max-time", "-o", "-output", "-rl", "-r", "-rL", "-config", "-pc", "-proxy"],
    invoke: { base: ["-silent"], perTarget: ["-d", "{{target}}"] },
    output: {
      format: "jsonl",
      ensureArgs: ["-oJ"],
      rules: [{ when: { host: "*" }, emit: [{ op: "upsert", kind: "domain", key: { fqdn: "{{host|lower}}" } }] }],
    },
    install: { method: "go", package: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
  },
  {
    name: "dnsx",
    description: "Fast DNS resolution of many names",
    binaries: ["dnsx", "~/go/bin/dnsx"],
    identity: PD_IDENTITY,
    risk: "passive",
    attack: ["T1590.002"],
    targets: { flags: ["-d", "-domain"], positional: false, fileFlags: ["-l", "-list"], form: "host" },
    valueFlags: ["-w", "-wordlist", "-r", "-resolver", "-t", "-threads", "-rl", "-o", "-output"],
    invoke: { base: ["-silent", "-a", "-aaaa", "-cname", "-resp"], perTarget: ["-d", "{{target}}"] },
    output: {
      format: "jsonl",
      ensureArgs: ["-json"],
      rules: [
        // Only names that exist: dnsx also prints the ones that do not (NXDOMAIN) when asked for JSON.
        { when: { host: "*", status_code: "NOERROR" }, emit: [{ op: "upsert", kind: "domain", key: { fqdn: "{{host|lower}}" } }] },
        {
          each: "a",
          emit: [
            { op: "upsert", kind: "host", key: { ip: "{{item|ip}}" }, attributes: { status: "unknown" } },
            { op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn: "{{host|lower}}" } }, to: { kind: "host", key: { ip: "{{item|ip}}" } } },
          ],
        },
        {
          each: "cname",
          emit: [
            { op: "upsert", kind: "domain", key: { fqdn: "{{item|undot|lower}}" } },
            { op: "relate", type: "alias_of", from: { kind: "domain", key: { fqdn: "{{host|lower}}" } }, to: { kind: "domain", key: { fqdn: "{{item|undot|lower}}" } } },
          ],
        },
      ],
    },
    install: { method: "go", package: "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" },
  },
  {
    name: "dig",
    description: "DNS lookups (A, AAAA, CNAME, MX, NS, TXT)",
    binaries: ["dig"],
    identity: { args: ["-v"], pattern: "DiG \\d" },
    risk: "passive",
    attack: ["T1590.002"],
    targets: { flags: ["-q", "-x"], positional: true, fileFlags: ["-f"], ignore: ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "ANY", "AXFR", "IN"], form: "host" },
    valueFlags: ["-p", "-t", "-c", "-b", "-k", "-y"],
    invoke: {
      base: ["+noall", "+answer"],
      perTarget: ["{{target}}", "A", "{{target}}", "AAAA", "{{target}}", "CNAME", "{{target}}", "MX", "{{target}}", "NS", "{{target}}", "TXT"],
    },
    output: {
      format: "lines",
      ensureArgs: [],
      rules: [
        {
          match: "^(?<name>\\S+)\\s+\\d+\\s+IN\\s+(?:A|AAAA)\\s+(?<value>\\S+)$",
          emit: [
            { op: "upsert", kind: "domain", key: { fqdn: "{{name|undot|lower}}" } },
            { op: "upsert", kind: "host", key: { ip: "{{value|ip}}" }, attributes: { status: "unknown" } },
            { op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn: "{{name|undot|lower}}" } }, to: { kind: "host", key: { ip: "{{value|ip}}" } } },
          ],
        },
        {
          match: "^(?<name>\\S+)\\s+\\d+\\s+IN\\s+CNAME\\s+(?<value>\\S+)$",
          emit: [
            { op: "upsert", kind: "domain", key: { fqdn: "{{value|undot|lower}}" } },
            { op: "relate", type: "alias_of", from: { kind: "domain", key: { fqdn: "{{name|undot|lower}}" } }, to: { kind: "domain", key: { fqdn: "{{value|undot|lower}}" } } },
          ],
        },
        {
          match: "^(?<name>\\S+)\\s+\\d+\\s+IN\\s+(?<type>MX|NS|TXT)\\s+(?<value>.+)$",
          emit: [
            {
              op: "upsert",
              kind: "domain",
              key: { fqdn: "{{name|undot|lower}}" },
              attributes: { records: [{ type: "{{type}}", value: "{{value|trim}}", observedAt: "{{_now}}" }] },
            },
          ],
        },
      ],
    },
    install: { method: "system", packages: { apt: "dnsutils", pacman: "bind", dnf: "bind-utils", zypper: "bind-utils", brew: "bind" } },
  },
  {
    name: "httpx",
    description: "HTTP probing: status, title, web server and technologies (ProjectDiscovery)",
    binaries: ["~/go/bin/httpx", "httpx"],
    identity: PD_IDENTITY,
    risk: "active",
    attack: ["T1595"],
    targets: { flags: ["-u", "-target"], positional: false, fileFlags: ["-l", "-list"] },
    valueFlags: ["-o", "-output", "-rl", "-t", "-threads", "-timeout", "-p", "-ports", "-path", "-H", "-x", "-mc", "-fc", "-ms", "-fs", "-proxy", "-http-proxy", "-r", "-resolvers"],
    // No -follow-redirects: following a redirect could reach an out-of-scope host.
    invoke: { base: ["-silent", "-title", "-tech-detect", "-status-code", "-web-server", "-ip"], perTarget: ["-u", "{{target}}"] },
    output: {
      format: "jsonl",
      ensureArgs: ["-json"],
      rules: [
        {
          when: { url: "*" },
          emit: [
            { op: "upsert", kind: "webapp", key: { origin: "{{url|origin}}" }, attributes: { title: "{{title}}" }, confidence: 0.9 },
            { op: "upsert", kind: "domain", key: { fqdn: "{{url|host|name|lower}}" } },
            { op: "relate", type: "hosted_at", from: { kind: "webapp", key: { origin: "{{url|origin}}" } }, to: { kind: "domain", key: { fqdn: "{{url|host|name|lower}}" } } },
          ],
        },
        {
          when: { url: "*", host: "*" },
          emit: [
            { op: "upsert", kind: "service", key: { ip: "{{host|ip}}", transport: "tcp", port: "{{url|port}}" }, attributes: { state: "open", protocol: "http" }, confidence: 0.9 },
            { op: "relate", type: "runs_on", from: { kind: "service", key: { ip: "{{host|ip}}", transport: "tcp", port: "{{url|port}}" } }, to: { kind: "host", key: { ip: "{{host|ip}}" } } },
            { op: "relate", type: "served_by", from: { kind: "webapp", key: { origin: "{{url|origin}}" } }, to: { kind: "service", key: { ip: "{{host|ip}}", transport: "tcp", port: "{{url|port}}" } } },
          ],
        },
        { when: { url: "*" }, each: "tech", emit: [{ op: "upsert", kind: "webapp", key: { origin: "{{url|origin}}" }, attributes: { technologies: [{ name: "{{item}}", confidence: 0.8 }] } }] },
        { when: { webserver: "*" }, emit: [{ op: "upsert", kind: "webapp", key: { origin: "{{url|origin}}" }, attributes: { technologies: [{ name: "{{webserver}}", confidence: 0.9 }] } }] },
        {
          when: { location: "*" },
          emit: [
            {
              op: "observe",
              title: "Redirects to {{location}}",
              sourceRule: "httpx:redirect",
              affects: [{ kind: "webapp", key: { origin: "{{url|origin}}" } }],
              severityHint: "info",
              detail: "HTTP {{status_code}} to {{location}}",
            },
          ],
        },
      ],
    },
    install: { method: "go", package: "github.com/projectdiscovery/httpx/cmd/httpx@latest" },
  },
  {
    name: "nuclei",
    description: "Template-based vulnerability scanner (ProjectDiscovery)",
    binaries: ["nuclei", "~/go/bin/nuclei"],
    identity: { args: ["-version"], pattern: "Nuclei Engine Version: v?[\\d.]+" },
    risk: "intrusive",
    attack: ["T1595.002"],
    targets: { flags: ["-u", "-target"], positional: false, fileFlags: ["-l", "-list"] },
    valueFlags: ["-t", "-templates", "-tags", "-etags", "-severity", "-s", "-es", "-o", "-rl", "-c", "-bs", "-timeout", "-retries", "-H", "-proxy", "-id", "-eid", "-w", "-workflows", "-type", "-pt", "-ept", "-a", "-author"],
    // Gentle by default: nuclei's own defaults (150 requests/s, 25 templates at once) are what
    // gets a tester's IP banned by the target's firewall. Pass -rl / -c to go faster on purpose.
    defaults: [["-rl", "20"], ["-c", "10"]],
    invoke: { base: ["-silent"], perTarget: ["-u", "{{target}}"] },
    output: {
      format: "jsonl",
      ensureArgs: ["-jsonl"],
      rules: [
        {
          when: { "template-id": "*", type: "http" },
          emit: [
            {
              op: "observe",
              title: "{{info.name}}",
              sourceRule: "nuclei:{{template-id}}",
              affects: [{ kind: "webapp", key: { origin: "{{matched-at|origin}}" } }],
              severityHint: "{{info.severity}}",
              detail: "{{info.description}}",
              location: "{{matched-at}}",
            },
          ],
        },
        ...(["dns", "ssl", "network", "tcp", "javascript"] as const).map((type) => ({
          when: { "template-id": "*", type },
          emit: [
            {
              op: "observe" as const,
              title: "{{info.name}}",
              sourceRule: "nuclei:{{template-id}}",
              affects: [{ kind: "domain" as const, key: { fqdn: "{{host|host|name|lower}}" } }],
              severityHint: "{{info.severity}}",
              detail: "{{info.description}}",
              location: "{{matched-at}}",
            },
          ],
        })),
      ],
    },
    install: { method: "go", package: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
  },
  {
    name: "katana",
    description: "Web crawler (ProjectDiscovery)",
    binaries: ["katana", "~/go/bin/katana"],
    identity: PD_IDENTITY,
    risk: "active",
    attack: ["T1595"],
    targets: { flags: ["-u", "-list"], positional: false, fileFlags: [] },
    valueFlags: ["-d", "-depth", "-o", "-rl", "-c", "-p", "-timeout", "-H", "-proxy"],
    invoke: { base: ["-silent"], perTarget: ["-u", "{{target}}"] },
    // Every URL the crawler finds becomes an endpoint of its application (out-of-scope ones are
    // recorded as such and never touched again).
    output: {
      format: "jsonl",
      ensureArgs: ["-jsonl"],
      rules: [
        {
          when: { "request.endpoint": "*" },
          emit: [
            { op: "upsert", kind: "webapp", key: { origin: "{{request.endpoint|origin}}" }, confidence: 0.9 },
            {
              op: "upsert",
              kind: "endpoint",
              key: { origin: "{{request.endpoint|origin}}", path: "{{request.endpoint|path}}" },
              attributes: { methods: ["{{request.method|upper}}"], statusesSeen: ["{{response.status_code|number}}"] },
              confidence: 0.9,
            },
          ],
        },
      ],
    },
    install: { method: "go", package: "github.com/projectdiscovery/katana/cmd/katana@latest" },
  },
  {
    name: "ffuf",
    description: "Web fuzzer for content and parameter discovery",
    binaries: ["ffuf", "~/go/bin/ffuf"],
    identity: { args: ["-V"], pattern: "ffuf version:? v?[\\d.]+" },
    risk: "intrusive",
    attack: ["T1595.003"],
    targets: { flags: ["-u"], positional: false, fileFlags: ["-request"] },
    valueFlags: ["-w", "-H", "-X", "-d", "-mc", "-fc", "-fs", "-fw", "-fl", "-t", "-rate", "-o", "-of", "-e", "-timeout", "-recursion-depth"],
    install: { method: "go", package: "github.com/ffuf/ffuf/v2@latest" },
  },
  {
    name: "gobuster",
    description: "Directory, DNS and vhost brute forcing",
    binaries: ["gobuster", "~/go/bin/gobuster"],
    identity: { args: ["version"], pattern: "\\d+\\.\\d+" },
    risk: "intrusive",
    attack: ["T1595.003"],
    targets: { flags: ["-u", "--url", "-d", "--domain"], positional: false, fileFlags: [] },
    valueFlags: ["-w", "--wordlist", "-t", "--threads", "-o", "-x", "-s", "-b", "-H", "--timeout"],
    install: { method: "go", package: "github.com/OJ/gobuster/v3@latest" },
  },
  {
    name: "sqlmap",
    description: "SQL injection detection and exploitation",
    binaries: ["sqlmap"],
    identity: { args: ["--version"], pattern: "^\\d+\\.\\d+" },
    risk: "exploitation",
    attack: ["T1190"],
    targets: { flags: ["-u", "--url"], positional: false, fileFlags: ["-m", "-r", "-l"] },
    valueFlags: ["--data", "--cookie", "-p", "--level", "--risk", "--technique", "--dbms", "-D", "-T", "-C", "--batch-size"],
    install: { method: "system", packages: { apt: "sqlmap", pacman: "sqlmap", dnf: "sqlmap", brew: "sqlmap" } },
  },
  {
    name: "curl",
    description: "HTTP client",
    binaries: ["curl"],
    identity: { args: ["--version"], pattern: "^curl \\d" },
    risk: "active",
    attack: ["T1595"],
    targets: { flags: ["--url"], positional: true, fileFlags: ["-K", "--config"] },
    // Options that take a value, so it is not read as a target. --resolve and --connect-to are left
    // out on purpose: they send the request to another address, so their value must be checked.
    valueFlags: [
      "-H", "--header", "-X", "--request", "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json",
      "-F", "--form", "--form-string", "--url-query", "-T", "--upload-file", "-o", "--output", "-m", "--max-time",
      "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-u", "--user", "-w", "--write-out",
      "--max-redirs", "--connect-timeout", "-x", "--proxy",
    ],
    install: { method: "system", packages: { apt: "curl", pacman: "curl", dnf: "curl", zypper: "curl", brew: "curl" } },
    // Maps response headers (with -i or -I) and robots.txt. One URL per call: the mapping uses the
    // run's target as the origin.
    output: {
      format: "lines",
      ensureArgs: [],
      rules: [
        { match: "^HTTP/[\\d.]+ (?<code>\\d{3})", emit: [{ op: "upsert", kind: "webapp", key: { origin: "{{target|origin}}" } }] },
        {
          match: "^(?:server|x-powered-by):\\s*(?<value>\\S.*)$",
          flags: "i",
          emit: [{ op: "upsert", kind: "webapp", key: { origin: "{{target|origin}}" }, attributes: { technologies: [{ name: "{{value|trim}}", confidence: 0.7 }] } }],
        },
        {
          match: "^location:\\s*(?<value>\\S+)",
          flags: "i",
          emit: [{ op: "observe", title: "Redirects to {{value}}", sourceRule: "http:redirect", affects: [{ kind: "webapp", key: { origin: "{{target|origin}}" } }], severityHint: "info" }],
        },
        {
          match: "^www-authenticate:\\s*(?<value>\\S.*)$",
          flags: "i",
          emit: [{ op: "observe", title: "Requests HTTP authentication: {{value|trim}}", sourceRule: "http:www-authenticate", affects: [{ kind: "webapp", key: { origin: "{{target|origin}}" } }], severityHint: "info" }],
        },
        {
          match: "^content-security-policy:\\s*(?<value>\\S.*)$",
          flags: "i",
          emit: [{ op: "observe", title: "Publishes a CSP policy", sourceRule: "http:csp", affects: [{ kind: "webapp", key: { origin: "{{target|origin}}" } }], severityHint: "info", detail: "{{value|trim}}" }],
        },
        {
          match: "^Disallow:\\s*(?<path>/\\S*)",
          flags: "i",
          emit: [
            { op: "upsert", kind: "endpoint", key: { origin: "{{target|origin}}", path: "{{path}}" } },
            { op: "observe", title: "robots.txt disallows {{path}}", sourceRule: "robots:disallow", affects: [{ kind: "endpoint", key: { origin: "{{target|origin}}", path: "{{path}}" } }], severityHint: "info" },
          ],
        },
      ],
    },
  },
  {
    name: "whatweb",
    description: "Web technology fingerprinting",
    binaries: ["whatweb"],
    identity: { args: ["--version"], pattern: "WhatWeb version [\\d.]+" },
    risk: "active",
    attack: ["T1592.002"],
    targets: { flags: [], positional: true, fileFlags: ["-i", "--input-file"] },
    valueFlags: ["-a", "--aggression", "-U", "--user-agent", "--log-json", "-t"],
    install: { method: "system", packages: { apt: "whatweb", brew: "whatweb" } },
  },
  {
    name: "nikto",
    description: "Web server scanner",
    binaries: ["nikto"],
    identity: { args: ["-Version"], pattern: "Nikto[^\\d]*[\\d.]+" },
    risk: "intrusive",
    attack: ["T1595.002"],
    targets: { flags: ["-h", "-host"], positional: false, fileFlags: [] },
    valueFlags: ["-p", "-port", "-o", "-Format", "-Tuning", "-timeout"],
    install: { method: "system", packages: { apt: "nikto", pacman: "nikto", dnf: "nikto", brew: "nikto" } },
  },
  {
    name: "netexec",
    description: "Network protocol attack tool (SMB, LDAP, WinRM…)",
    binaries: ["nxc", "netexec"],
    identity: { args: ["--version"], pattern: "\\d+\\.\\d+" },
    risk: "exploitation",
    attack: ["T1021", "T1110"],
    targets: { flags: [], positional: true, fileFlags: [], ignore: ["smb", "ldap", "winrm", "ssh", "mssql", "rdp", "ftp", "wmi", "vnc", "nfs"] },
    valueFlags: ["-u", "-p", "-H", "-d", "--port", "-M", "-o"],
    install: { method: "manual", command: "pipx install git+https://github.com/Pennyw0rth/NetExec" },
  },
];
