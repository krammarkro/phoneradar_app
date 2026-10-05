from __future__ import annotations

import asyncio
import ctypes
import ipaddress
import socket
import sys
from collections.abc import Collection
from typing import Any, Literal

PacketAction = Literal["client_redirected", "reply_rewritten", "upstream_passthrough", "unchanged"]


def rewrite_local_udp_packet(
    packet: Any,
    *,
    upstream_address: str,
    upstream_port: int,
    listen_port: int,
    upstream_source_ports: Collection[int],
) -> PacketAction:
    """Rewrite one local IPv4 UDP packet for the explicit relay socket."""
    if getattr(packet, "ipv4", None) is None or getattr(packet, "udp", None) is None:
        return "unchanged"

    if packet.dst_addr == upstream_address and packet.dst_port == upstream_port:
        if packet.src_port in upstream_source_ports:
            return "upstream_passthrough"
        if packet.src_addr is None:
            return "unchanged"
        packet.dst_addr = packet.src_addr
        packet.dst_port = listen_port
        return "client_redirected"

    if (
        packet.src_port == listen_port
        and packet.src_addr is not None
        and packet.src_addr == packet.dst_addr
    ):
        packet.src_addr = upstream_address
        packet.src_port = upstream_port
        return "reply_rewritten"

    return "unchanged"


class WindowsUdpRedirector:
    def __init__(self, upstream_host: str, upstream_port: int, listen_port: int, relay: Any) -> None:
        self.upstream_address = str(ipaddress.IPv4Address(socket.gethostbyname(upstream_host)))
        self.upstream_port = upstream_port
        self.listen_port = listen_port
        self._relay = relay
        self._ready: asyncio.Future[None] | None = None

    @property
    def filter(self) -> str:
        return (
            "outbound and !impostor and udp and "
            f"((ip.DstAddr == {self.upstream_address} and udp.DstPort == {self.upstream_port}) or "
            f"udp.SrcPort == {self.listen_port})"
        )

    async def start(self) -> asyncio.Task[None]:
        if sys.platform != "win32":
            raise OSError("transparent UDP redirection is only available on Windows")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("transparent UDP redirection requires an Administrator terminal")

        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        task = loop.create_task(self._run())
        try:
            await self._ready
        except BaseException:
            await task
            raise
        return task

    async def _run(self) -> None:
        try:
            import pydivert
        except ImportError as error:
            setup_error = RuntimeError(
                'install transparent-mode support with: python -m pip install -e ".[transparent-windows]"'
            )
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(setup_error)
            raise setup_error from error

        try:
            async with pydivert.Divert(self.filter) as diverter:
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(None)
                async for packet in diverter:
                    action = rewrite_local_udp_packet(
                        packet,
                        upstream_address=self.upstream_address,
                        upstream_port=self.upstream_port,
                        listen_port=self.listen_port,
                        upstream_source_ports=self._relay.upstream_source_ports,
                    )
                    await diverter.send_async(packet)
                    if action == "client_redirected":
                        print(
                            f"redirected local UDP {packet.src_addr}:{packet.src_port} "
                            f"to relay {packet.dst_addr}:{packet.dst_port}",
                            flush=True,
                        )
                    elif action == "reply_rewritten":
                        print(
                            f"rewrote relay reply as {packet.src_addr}:{packet.src_port} "
                            f"to {packet.dst_addr}:{packet.dst_port}",
                            flush=True,
                        )
        except BaseException as error:
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(error)
            raise