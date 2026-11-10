# @penteos/desktop

The Penteos workbench: an Electron app with a React interface. It starts the core
(`packages/server`) as a child process and talks to it over HTTP and WebSocket, or connects to a
team server instead.

```
electron/        Main process: windows, the core's lifecycle, the project browser, the agents'
                 browser host, native dialogs, PDF export
src/             The interface: shell, panels, i18n catalogs (es, en), styles
scripts/         dev.mjs (pnpm dev) and package.mjs (Linux packages)
build-resources/ Icons, the AppArmor profile and the launcher of the Linux packages
```

Run it with `pnpm dev` from the repository root. Build the Linux packages with
`pnpm --filter @penteos/desktop package` (output in `release/`); release builds use
`scripts/release/` instead, inside a container, so they run on any distribution.
