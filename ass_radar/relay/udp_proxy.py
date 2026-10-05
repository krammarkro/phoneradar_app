from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from dataclasses import dataclass
from typing import Any

from ass_radar.relay.processor import RelayPhotonProcessor

ClientAddress = tuple[Any, ...]


@dataclass
class _UdpSession:
    client_address: ClientAddress
    upstream_transport: asyncio.DatagramTransport
    upstream_source_port: int
    processor: RelayPhotonProcessor
    expiry_handle: asyncio.TimerHandle | None = None


class _UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, relay: UdpRelay, client_address: ClientAddress) -> None:
        self._relay = relay
        self._client_address = client_address
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: ClientAddress) -> None:
        self._relay._from_upstream(self._client_address, data)

    def error_received(self, exc: Exception) -> None:
        print(f"upstream UDP error for {self._client_address}: {exc}", file=sys.stderr)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            print(f"upstream UDP connection lost for {self._client_address}: {exc}", file=sys.stderr)
        self._relay._upstream_lost(self._client_address)


class UdpRelay(asyncio.DatagramProtocol):
    """Forward UDP datagrams through one Photon processor per client."""

    def __init__(self, upstream_host: str, upstream_port: int, idle_timeout: float = 120.0) -> None:
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._idle_timeout = idle_timeout
        self._listener: asyncio.DatagramTransport | None = None
        self._sessions: dict[ClientAddress, _UdpSession] = {}
        self._pending: dict[ClientAddress, list[bytes]] = {}
        self._upstream_source_ports: set[int] = set()
        self._upstream_source_ports_lock = threading.Lock()

    @property
    def upstream_source_ports(self) -> frozenset[int]:
        with self._upstream_source_ports_lock:
            return frozenset(self._upstream_source_ports)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._listener = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: ClientAddress) -> None:
        address = addr
        print(f"relay received {len(data)} bytes from {address}", flush=True)
        session = self._sessions.get(address)
        if session is not None:
            self._touch_session(session)
            self._send_to_upstream(session, data)
            return

        pending = self._pending.get(address)
        if pending is not None:
            if len(pending) < 64:
                pending.append(data)
            return

        self._pending[address] = [data]
        asyncio.get_running_loop().create_task(self._open_session(address))

    def error_received(self, exc: Exception) -> None:
        print(f"client UDP socket error: {exc}", file=sys.stderr)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            print(f"client UDP socket closed: {exc}", file=sys.stderr)

    async def _open_session(self, address: ClientAddress) -> None:
        protocol = _UpstreamProtocol(self, address)
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(self._upstream_host, self._upstream_port),
            )
        except (OSError, asyncio.CancelledError) as error:
            self._pending.pop(address, None)
            if isinstance(error, OSError):
                print(f"could not open upstream UDP flow for {address}: {error}", file=sys.stderr)
            else:
                raise
            return

        upstream_source_port = int(transport.get_extra_info("sockname")[1])
        with self._upstream_source_ports_lock:
            self._upstream_source_ports.add(upstream_source_port)
        session = _UdpSession(
            client_address=address,
            upstream_transport=transport,  # type: ignore[arg-type]
            upstream_source_port=upstream_source_port,
            processor=RelayPhotonProcessor(
                on_event=lambda event: print(json.dumps(event, separators=(",", ":")), flush=True),
                strict_transport=True,
                event_source="local_relay",
            ),
        )
        self._sessions[address] = session
        self._touch_session(session)
        for payload in self._pending.pop(address, []):
            self._send_to_upstream(session, payload)

    def _send_to_upstream(self, session: _UdpSession, payload: bytes) -> None:
        try:
            outputs = session.processor.process_packets(direction="client_to_upstream", payload=payload)
            print(f"relay forwarding {len(outputs)} packet(s) upstream for {session.client_address}", flush=True)
            for output in outputs:
                session.upstream_transport.sendto(output)
        except Exception as error:
            print(f"stopping unsafe UDP flow for {session.client_address}: {error}", file=sys.stderr)
            self._close_session(session.client_address)

    def _from_upstream(self, address: ClientAddress, payload: bytes) -> None:
        session = self._sessions.get(address)
        if session is None:
            return
        self._touch_session(session)
        print(f"relay received {len(payload)} bytes from upstream for {address}", flush=True)
        try:
            outputs = session.processor.process_packets(direction="upstream_to_client", payload=payload)
            print(f"relay forwarding {len(outputs)} packet(s) to {address}", flush=True)
            if self._listener is not None:
                for output in outputs:
                    self._listener.sendto(output, address)
        except Exception as error:
            print(f"stopping unsafe UDP flow for {address}: {error}", file=sys.stderr)
            self._close_session(address)

    def _touch_session(self, session: _UdpSession) -> None:
        if session.expiry_handle is not None:
            session.expiry_handle.cancel()
        session.expiry_handle = asyncio.get_running_loop().call_later(
            self._idle_timeout,
            self._close_session,
            session.client_address,
        )

    def _upstream_lost(self, address: ClientAddress) -> None:
        self._close_session(address, close_upstream=False)

    def _close_session(self, address: ClientAddress, *, close_upstream: bool = True) -> None:
        session = self._sessions.pop(address, None)
        if session is None:
            return
        if session.expiry_handle is not None:
            session.expiry_handle.cancel()
        with self._upstream_source_ports_lock:
            self._upstream_source_ports.discard(session.upstream_source_port)
        session.processor.finalize()
        if close_upstream:
            session.upstream_transport.close()

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        for address in tuple(self._sessions):
            self._close_session(address)
        self._pending.clear()


async def serve_udp_relay(
    *,
    upstream_host: str,
    upstream_port: int = 5056,
    listen_host: str = "0.0.0.0",
    listen_port: int = 5056,
    idle_timeout: float = 120.0,
    transparent: bool = False,
) -> None:
    relay = UdpRelay(upstream_host, upstream_port, idle_timeout)
    redirector = None
    if transparent:
        from ass_radar.relay.windows_redirect import WindowsUdpRedirector

        redirector = WindowsUdpRedirector(upstream_host, upstream_port, listen_port, relay)
        upstream_host = redirector.upstream_address
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: relay,
        local_addr=(listen_host, listen_port),
    )
    redirect_task: asyncio.Task[None] | None = None
    try:
        if redirector is not None:
            redirect_task = await redirector.start()
        print(
            f"UDP relay listening on {listen_host}:{listen_port}, forwarding to {upstream_host}:{upstream_port}"
            + (" with transparent Windows redirection" if redirector is not None else ""),
            flush=True,
        )
        if redirect_task is None:
            await asyncio.Future()
        else:
            await redirect_task
    finally:
        if redirect_task is not None and not redirect_task.done():
            redirect_task.cancel()
            try:
                await redirect_task
            except asyncio.CancelledError:
                pass
        relay.close()
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Relay live UDP traffic through the Photon processor.")
    parser.add_argument("--upstream-host", required=True, help="Destination game server hostname or IP")
    parser.add_argument("--upstream-port", type=int, default=5056)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=5056)
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    parser.add_argument(
        "--transparent",
        action="store_true",
        help="intercept local Windows UDP traffic to the upstream server (requires Administrator)",
    )
    args = parser.parse_args()
    if not 1 <= args.upstream_port <= 65535 or not 1 <= args.listen_port <= 65535:
        parser.error("UDP ports must be between 1 and 65535")
    if args.idle_timeout <= 0:
        parser.error("idle timeout must be positive")
    try:
        asyncio.run(
            serve_udp_relay(
                upstream_host=args.upstream_host,
                upstream_port=args.upstream_port,
                listen_host=args.listen_host,
                listen_port=args.listen_port,
                idle_timeout=args.idle_timeout,
                transparent=args.transparent,
            )
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()