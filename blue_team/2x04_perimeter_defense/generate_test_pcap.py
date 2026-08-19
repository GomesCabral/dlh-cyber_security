#!/usr/bin/env python3
"""Generate a harmless PCAP with deterministic Suricata test traffic."""

from pathlib import Path
import socket
import struct
import time

OUT = Path(__file__).with_name("mixed_traffic_test.pcap")
packets: list[tuple[float, bytes]] = []
now = time.time()


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(ip_packet: bytes, src_last: int, dst_last: int) -> bytes:
    src = bytes.fromhex("0200000000") + bytes([src_last])
    dst = bytes.fromhex("0200000000") + bytes([dst_last])
    return dst + src + struct.pack("!H", 0x0800) + ip_packet


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, 64, proto, 0, src_b, dst_b)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"") -> bytes:
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    header = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 0x50, flags,
                         64240, 0, 0)
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    check = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", check) + header[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, len(header) + len(payload))
    check = checksum(pseudo + header + payload)
    return header[:6] + struct.pack("!H", check or 0xFFFF) + payload


def add_tcp_flow(src: str, dst: str, sport: int, dport: int, payload: bytes,
                 src_mac: int, dst_mac: int, ident: int) -> None:
    global now
    # Complete handshake, client payload, ACK and graceful close.
    segments = [
        (src, dst, sport, dport, 1000, 0, 0x02, b"", src_mac, dst_mac),
        (dst, src, dport, sport, 5000, 1001, 0x12, b"", dst_mac, src_mac),
        (src, dst, sport, dport, 1001, 5001, 0x10, b"", src_mac, dst_mac),
        (src, dst, sport, dport, 1001, 5001, 0x18, payload, src_mac, dst_mac),
        (dst, src, dport, sport, 5001, 1001 + len(payload), 0x10, b"", dst_mac, src_mac),
        (src, dst, sport, dport, 1001 + len(payload), 5001, 0x11, b"", src_mac, dst_mac),
    ]
    for offset, segment in enumerate(segments):
        s, d, sp, dp, seq, ack, flags, body, sm, dm = segment
        frame = ethernet(ipv4(s, d, 6, tcp(s, d, sp, dp, seq, ack, flags, body),
                              ident + offset), sm, dm)
        packets.append((now, frame))
        now += 0.001


def dns_query(name: str, txid: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    # Standard recursive query, QTYPE TXT (16), QCLASS IN (1).
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 16, 1)


# 1. Benign MedDefense HTTP traffic (should not match the local test rules).
add_tcp_flow("10.10.1.20", "10.10.1.30", 41000, 80,
             b"GET /health HTTP/1.1\r\nHost: meddefense.local\r\nUser-Agent: MedDefense-Monitor/1.0\r\n\r\n",
             20, 30, 100)

# 2. Reconnaissance probe.
add_tcp_flow("10.10.1.99", "10.10.1.10", 42000, 80,
             b"GET / HTTP/1.1\r\nHost: 10.10.1.10\r\nUser-Agent: Nmap Scripting Engine\r\n\r\n",
             99, 10, 200)

# 3. Harmless SMB byte sequence representing a PsExec service-install attempt.
add_tcp_flow("10.10.1.99", "10.10.1.10", 49152, 445,
             b"\x00\x00\x00\x30SMB2_TEST_ONLY_SERVICE=PSEXESVC;ACTION=INSTALL",
             99, 10, 300)

# 4. Harmless HTTP beacon marker; no connection to a real malicious server.
add_tcp_flow("10.10.1.10", "203.0.113.42", 51000, 8080,
             b"POST /beacon HTTP/1.1\r\nHost: test.invalid\r\nUser-Agent: MedDefense-Cobalt-Test\r\nContent-Length: 11\r\n\r\nBEACON_TEST",
             10, 42, 400)

# 5. Three long DNS TXT queries representing tunneling/exfiltration.
for index in range(3):
    label = ("deadbeef" * 7) + f"{index:02d}"
    query = dns_query(f"{label}.exfil.test", 0x6000 + index)
    frame = ethernet(ipv4("10.10.1.10", "8.8.8.8", 17,
                          udp("10.10.1.10", "8.8.8.8", 53000 + index, 53, query),
                          500 + index), 10, 8)
    packets.append((now, frame))
    now += 0.010

with OUT.open("wb") as handle:
    # PCAP, little-endian, microsecond timestamps, Ethernet link type.
    handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for timestamp, frame in packets:
        seconds = int(timestamp)
        micros = int((timestamp - seconds) * 1_000_000)
        handle.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
        handle.write(frame)

print(f"Created {OUT} with {len(packets)} packets")
