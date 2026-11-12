"""Bounded SOCKS5 CONNECT proxy for an isolated native runtime (TCP only)."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress


async def serve_client(reader, writer):
    remote = None
    try:
        async def handshake():
            nonlocal remote
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            if version != 5 or 0 not in methods:
                writer.write(b'\x05\xff')
                await writer.drain()
                return
            writer.write(b'\x05\x00')
            await writer.drain()
            version, command, reserved, kind = await reader.readexactly(4)
            if version != 5 or reserved != 0:
                return
            if command != 1:
                writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)
                await writer.drain()
                return
            if kind in (1, 4):
                host = str(ipaddress.ip_address(await reader.readexactly(4 if kind == 1 else 16)))
            elif kind == 3:
                length = (await reader.readexactly(1))[0]
                if not length:
                    return
                host = (await reader.readexactly(length)).decode('ascii')
                if '\x00' in host:
                    return
            else:
                writer.write(b'\x05\x08\x00\x01' + b'\x00' * 6)
                await writer.drain()
                return
            port = int.from_bytes(await reader.readexactly(2), 'big')
            try:
                upstream, remote = await asyncio.open_connection(host, port)
            except (OSError, ValueError):
                writer.write(b'\x05\x05\x00\x01' + b'\x00' * 6)
                await writer.drain()
                return
            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()
            return upstream
        upstream = await asyncio.wait_for(handshake(), timeout=15)
        if upstream is None:
            return
        async def relay(source, target):
            while data := await source.read(65536):
                target.write(data)
                await target.drain()
            if target.can_write_eof():
                target.write_eof()
        await asyncio.wait_for(asyncio.gather(relay(reader, remote), relay(upstream, writer)), timeout=3600)
    except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        pass
    finally:
        for stream in (remote, writer):
            if stream:
                stream.close()
                try:
                    await stream.wait_closed()
                except OSError:
                    pass


async def main_async(host, port):
    # Bound accepted sessions, including incomplete handshakes.
    active = set()
    def accept(reader, writer):
        if len(active) >= 128:
            writer.close()
            return
        task = asyncio.create_task(serve_client(reader, writer))
        active.add(task)
        task.add_done_callback(active.discard)
    server = await asyncio.start_server(accept, host, port, limit=65536)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=1080)
    args = parser.parse_args()
    asyncio.run(main_async(args.listen, args.port))


if __name__ == '__main__':
    main()
