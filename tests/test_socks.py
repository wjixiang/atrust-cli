import asyncio
import pytest
from atrust_cli.socks import serve_client


@pytest.mark.parametrize('domain', [False, True])
def test_socks_tcp_roundtrip_and_half_close(domain):
    async def run():
        async def echo(reader, writer):
            data = await reader.read()
            writer.write(data.upper())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        echo_server = await asyncio.start_server(echo, '127.0.0.1', 0)
        proxy = await asyncio.start_server(serve_client, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', proxy.sockets[0].getsockname()[1])
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            assert await reader.readexactly(2) == b'\x05\x00'
            target = b'\x03\x09localhost' if domain else b'\x01\x7f\x00\x00\x01'
            writer.write(b'\x05\x01\x00' + target + echo_server.sockets[0].getsockname()[1].to_bytes(2, 'big'))
            await writer.drain()
            assert (await reader.readexactly(10))[1] == 0
            writer.write(b'hello through tunnel')
            await writer.drain()
            writer.write_eof()
            assert await reader.read() == b'HELLO THROUGH TUNNEL'
            writer.close()
            await writer.wait_closed()
        finally:
            proxy.close()
            echo_server.close()
            await proxy.wait_closed()
            await echo_server.wait_closed()
    asyncio.run(asyncio.wait_for(run(), 10))


@pytest.mark.parametrize('packet,expected', [
    (b'\x05\x01\x02', b'\x05\xff'),
    (b'\x05\x01\x00\x05\x03\x00\x01', b'\x05\x00\x05\x07'),
    (b'\x05\x01\x00\x05\x01\x00\x09', b'\x05\x00\x05\x08'),
])
def test_socks_rejects_auth_udp_and_unknown_address(packet, expected):
    async def run():
        server = await asyncio.start_server(serve_client, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(packet)
            await writer.drain()
            assert (await reader.read()).startswith(expected)
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(asyncio.wait_for(run(), 5))
