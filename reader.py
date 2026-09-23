###################################################
#
#                PCAP FILE READER
#
###################################################

"""

Responsabilidad de este archivo:
  - Leer el .pcap capturado.
  - Encontrar los paquetes RIPv2 (UDP puerto 520) que traen el
    trailer de autenticación MD5 (RFC 2082).
  - Extraer, por cada paquete autenticado:
        * el payload RIP "crudo" (para que el maestro/workers puedan
          recalcular el HMAC sobre él),
        * el Key ID,
        * el Sequence Number,
        * el digest (hash) que se debe intentar reproducir.
  - Guardar todo en un JSON para que el archivo "master.py" lo lea
    y reparta el trabajo a los workers.

"""

import json
import sys
from scapy.all import rdpcap, UDP, IP

RIP_PORT = 520
AUTH_AFI = 0xFFFF          # marca "esto no es una ruta, es auth"
AUTH_TYPE_MD5 = 3          # tipo de auth en la cabecera (RFC 2082)
TRAILER_AUTH_TYPE = 1      # tipo de auth en el trailer final
MD5_DIGEST_LEN = 16        # HMAC-MD5 siempre son 16 bytes


def parse_rip_auth_packet(raw: bytes):
    """
    Dado el payload UDP crudo de UN paquete RIP, intenta extraer
    los datos de autenticación MD5. Devuelve None si el paquete
    no trae autenticación (ej. los 'request' vacíos).
    """
    if len(raw) < 24 + MD5_DIGEST_LEN:
        return None  # muy corto para traer auth + digest

    command = raw[0]
    version = raw[1]

    # La primera "RTE" (bytes 4 a 23) es en realidad la cabecera de auth
    first_rte = raw[4:24]
    afi = int.from_bytes(first_rte[0:2], "big")
    auth_type = int.from_bytes(first_rte[2:4], "big")

    if afi != AUTH_AFI or auth_type != AUTH_TYPE_MD5:
        return None  # no es un paquete autenticado

    key_id = first_rte[6]
    seq_number = int.from_bytes(first_rte[8:12], "big")

    # El digest SIEMPRE son los últimos 16 bytes del paquete
    digest = raw[-MD5_DIGEST_LEN:]
    trailer_marker = raw[-(MD5_DIGEST_LEN + 4):-MD5_DIGEST_LEN]
    trailer_afi = int.from_bytes(trailer_marker[0:2], "big")
    trailer_type = int.from_bytes(trailer_marker[2:4], "big")

    if trailer_afi != AUTH_AFI or trailer_type != TRAILER_AUTH_TYPE:
        return None  # el paquete estaba corrupto o mal formado

    """
    "hmac_base": el payload sobre el cual se calculó originalmente el
    HMAC. Según RFC 2082, es TODO el paquete RIP (header + auth header
    + RTEs) SIN el trailer final, y con el campo de digest sustituido
    por el valor de la clave/keystring durante el cálculo real del
    HMAC
    """
    hmac_base = raw[: -(MD5_DIGEST_LEN + 4)]

    return {
        "command": command,
        "version": version,
        "key_id": key_id,
        "seq_number": seq_number,
        "digest_hex": digest.hex(),
        "hmac_base_hex": hmac_base.hex(),
        "raw_packet_hex": raw.hex(),
    }


def extract_from_pcap(pcap_path: str):
    packets = rdpcap(pcap_path)
    results = []

    # si este paquete no es tipo UDP, se salta
    # si es UDP pero no usa el puerto 520 se salta
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(UDP):
            continue
        if pkt[UDP].sport != RIP_PORT or pkt[UDP].dport != RIP_PORT:
            continue

        # si no tenia auth se salta tmb
        raw = bytes(pkt[UDP].payload)
        parsed = parse_rip_auth_packet(raw)
        if parsed is None:
            continue

        # se agregan dos dts extra: en que posición del pcap estaba, y quién lo mando / a quién iba
        parsed["packet_index"] = i
        if pkt.haslayer(IP):
            parsed["src_ip"] = pkt[IP].src
            parsed["dst_ip"] = pkt[IP].dst

        results.append(parsed)

    return results


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 pickup.py <archivo.pcap> [salida.json]")
        sys.exit(1)

    # si no le pones nombre, usa el de pickup_output.json
    pcap_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "pickup_output.json"

    entries = extract_from_pcap(pcap_path)

    # por si viene vacío
    if not entries:
        print("No se encontraron paquetes RIP autenticados en el pcap.")
        sys.exit(1)

    # para ver que se encontro, no tiene utilidad
    print(f"Se encontraron {len(entries)} paquetes RIP autenticados (MD5).")
    print("\nResumen:")
    for e in entries:
        print(
            f"  paquete #{e['packet_index']:>3} | "
            f"src={e.get('src_ip'):<12} | "
            f"key_id={e['key_id']} | "
            f"seq={e['seq_number']:<3} | "
            f"digest={e['digest_hex']}"
        )

    # escrito en json bonito
    with open(out_path, "w") as f:
        json.dump(entries, f, indent=2)

    #aout_path archivo para 'maestro'
    print(f"\nGuardado en '{out_path}'")


if __name__ == "__main__":
    main()