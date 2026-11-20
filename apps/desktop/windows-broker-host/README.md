# CyberAudit Windows broker host

This fixed-purpose, self-contained .NET 10 host embeds Microsoft Garnet 2.2.8 for
the Windows x64 desktop runtime. It is not a general Redis server launcher and
does not accept user-controlled commands, configuration files or executable
paths.

The Tauri supervisor supplies an allowlisted loopback port, private data
directory and per-installation 256-bit broker password obtained from Windows
Credential Manager. The password is delivered once over an inherited standard
input pipe; it is never placed in process arguments, the process environment or
a configuration file. The host validates it and configures Garnet in memory.

The server is loopback-only, password authenticated, AOF-backed, recovery
fail-closed and Lua-enabled because Dramatiq 1.x implements its Redis broker
protocol with two bundled Lua scripts. The Windows native pipeline must run the
real Dramatiq interoperability and restart-durability checks before it is
allowed to build an installer.

Microsoft Garnet is licensed under the MIT License. The pinned upstream source
tag is `v2.2.8` (`5cc8f3f50aa57ed694dfda928e4467593e073656`).
