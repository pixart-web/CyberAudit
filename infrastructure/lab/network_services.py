"""Inert TCP banner services for the isolated CyberAudit development lab.

These listeners do not implement SSH, PostgreSQL or Redis, accept no commands,
hold no credentials and never contact another destination.
"""

from __future__ import annotations

import asyncio

BANNERS = {
    2222: b"SSH-2.0-CyberAudit-Demo_1.0\r\n",
    5433: b"CYBERAUDIT DEMO DATABASE SERVICE - NO PROTOCOL\r\n",
    6380: b"-CYBERAUDIT DEMO CACHE - COMMANDS DISABLED\r\n",
}


async def handle(
    _reader: asyncio.StreamReader, writer: asyncio.StreamWriter, banner: bytes
) -> None:
    writer.write(banner)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main() -> None:
    servers = [
        await asyncio.start_server(
            lambda reader, writer, value=banner: handle(reader, writer, value),
            "0.0.0.0",
            port,
        )
        for port, banner in BANNERS.items()
    ]
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
