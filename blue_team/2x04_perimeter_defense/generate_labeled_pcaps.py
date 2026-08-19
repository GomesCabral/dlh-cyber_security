#!/usr/bin/env python3
"""Create safe labeled PCAPs for Task 10 (requires Scapy)."""

from pathlib import Path
from math import ceil
import time

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, Raw, PcapWriter  # type: ignore

OUT = Path(__file__).resolve().parent / "labels"
OUT.mkdir(parents=True, exist_ok=True)
BASE = time.time()


def stamp(packet, offset):
    packet.time = BASE + offset
    return packet


def tcp_flow(src, dst, sport, dport, payload=b"", offset=0.0):
    """Return a valid handshake, optional client payload, ACK and FIN."""
    client_seq, server_seq = 1000, 5000
    packets = [
        stamp(Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
              flags="S", seq=client_seq), offset),
        stamp(Ether()/IP(src=dst, dst=src)/TCP(sport=dport, dport=sport,
              flags="SA", seq=server_seq, ack=client_seq + 1), offset + .001),
        stamp(Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
              flags="A", seq=client_seq + 1, ack=server_seq + 1), offset + .002),
    ]
    if payload:
        packets.extend([
            stamp(Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
                  flags="PA", seq=client_seq + 1, ack=server_seq + 1)/Raw(payload),
                  offset + .003),
            stamp(Ether()/IP(src=dst, dst=src)/TCP(sport=dport, dport=sport,
                  flags="A", seq=server_seq + 1, ack=client_seq + 1 + len(payload)),
                  offset + .004),
        ])
    return packets


def write(name, packets):
    writer = PcapWriter(str(OUT / name), linktype=1, sync=True)
    for packet in packets:
        writer.write(packet)
    writer.close()
    print(f"[+] {name}: {len(packets)} packets")


# Both MEDDEV custom rules fire. UDP/123 is included as a negative control and
# must not create an alert.
meddev = tcp_flow("10.10.4.25", "203.0.113.10", 40000, 443, b"TEST", 0)
meddev += [
    stamp(Ether()/IP(src="10.10.4.25", dst="198.51.100.10")/
          UDP(sport=41000, dport=4444)/Raw(b"TEST_UDP_EGRESS"), .010),
    stamp(Ether()/IP(src="10.10.4.25", dst="192.0.2.123")/
          UDP(sport=41001, dport=123)/Raw(b"NTP_ALLOWED_CONTROL"), .011),
]
write("meddev_egress.pcap", meddev)

write("guest_smb.pcap", tcp_flow(
    "10.10.5.25", "10.10.1.10", 42000, 445, b"SMB_TEST", .100))

long_label = "a" * 51
dns_packets = []
for index in range(3):
    dns_packets.append(stamp(
        Ether()/IP(src="10.10.2.25", dst="8.8.8.8")/
        UDP(sport=53000 + index, dport=53)/
        DNS(id=0x7000 + index, rd=1,
            qd=DNSQR(qname=f"{long_label}{index}.tunnel.test", qtype="TXT")),
        .200 + index * .01))
write("dns_tunnel.pcap", dns_packets)

write("clinical_wrong_db.pcap", tcp_flow(
    "10.10.2.25", "10.10.1.60", 43000, 3306, b"MYSQL_TEST", .300))

write("telnet_meddev.pcap", tcp_flow(
    "10.10.2.25", "10.10.4.30", 44000, 23, b"admin\r\n", .400))

# Produce >50 MiB of client TCP payload in under 300 seconds. ACK every segment
# so the stream remains plausible and within the advertised receive window.
large_path = OUT / "large_outbound.pcap"
writer = PcapWriter(str(large_path), linktype=1, sync=True)
src, dst, sport, dport = "10.10.1.10", "203.0.113.42", 45000, 443
client_seq, server_seq = 1000, 9000
handshake = tcp_flow(src, dst, sport, dport, b"", .500)
for packet in handshake:
    writer.write(packet)

payload = b"X" * 1460
target_bytes = 50 * 1024 * 1024 + 1460
segments = ceil(target_bytes / len(payload))
seq = client_seq + 1
for index in range(segments):
    moment = .503 + index * .006
    data = stamp(Ether()/IP(src=src, dst=dst)/TCP(
        sport=sport, dport=dport, flags="PA", seq=seq, ack=server_seq + 1)/
        Raw(payload), moment)
    ack = stamp(Ether()/IP(src=dst, dst=src)/TCP(
        sport=dport, dport=sport, flags="A", seq=server_seq + 1,
        ack=seq + len(payload)), moment + .003)
    writer.write(data)
    writer.write(ack)
    seq += len(payload)
writer.close()
print(f"[+] large_outbound.pcap: {3 + segments * 2} packets, "
      f"{segments * len(payload)} TCP payload bytes")