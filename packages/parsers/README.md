# Parsers

One package per tool. Each parser reads a tool's raw output and emits an ingest batch in the
`penteos.ingest/v0` format (defined in `packages/schema/src/ingest.ts`), with fixtures of real
output and the expected batch as tests.

- `nmap/` - nmap XML (`-oX`)
- `bloodhound/` - SharpHound / BloodHound collections (ZIP or JSON)
