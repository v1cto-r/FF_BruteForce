###################################################
#
#       CLIENT THAT CONNECTS VIA SOCKETS (client.py)
#
###################################################

import socket
import json
import hmac
import hashlib

# Configuration settings
SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432

def compute_hmac_md5(key_str, payload_bytes):
    """Calculates HMAC-MD5 signature for a given candidate key string."""
    key_bytes = key_str.encode('utf-8')
    return hmac.new(key_bytes, payload_bytes, hashlib.md5).hexdigest()

def process_work_assignment(command, client_socket):
    """Processes an ASSIGN_WORK command and executes the brute-force search."""
    start_int = int(command["start_hex"], 16)
    end_int = int(command["end_hex"], 16)
    target_hmac = command["target_hmac"]
    payload_bytes = bytes.fromhex(command["payload_hex"])
    
    # Read dynamic key length provided by server.py (defaults to 6 if not provided)
    key_length = command.get("key_length", 6)
    format_spec = f"0{key_length}x"

    print(f"[*] Testing range {hex(start_int)} to {hex(end_int)} (Key length: {key_length})")

    for current_int in range(start_int, end_int + 1):
        # Format candidate string to the specified zero-padded length
        candidate_key = format(current_int, format_spec)
        calculated_hmac = compute_hmac_md5(candidate_key, payload_bytes)

        if calculated_hmac.lower() == target_hmac.lower():
            print(f"[!] Key found: {candidate_key}")
            
            # Inform the server that the key was found
            found_msg = json.dumps({
                "action": "KEY_FOUND",
                "key": candidate_key
            }) + "\n"
            client_socket.sendall(found_msg.encode('utf-8'))
            return True

    print("[*] Range completed without matches.")
    return False

# 1. Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 2. Connect to the server
client_socket.connect((SERVER_IP, SERVER_PORT))
print(f"[+] Connected to server at {SERVER_IP}:{SERVER_PORT}")

buffer = ""

try:
    while True:
        # 3. Send a message (Requesting work from server)
        request_msg = json.dumps({"action": "REQUEST_WORK"}) + "\n"
        client_socket.sendall(request_msg.encode('utf-8'))

        # 4. Receive the reply
        reply = client_socket.recv(4096)
        if not reply:
            print("[-] Connection closed by server.")
            break

        buffer += reply.decode('utf-8')

        # Process received newline-delimited JSON messages
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip():
                continue

            command = json.loads(line)
            action = command.get("action")

            if action == "ASSIGN_WORK":
                found = process_work_assignment(command, client_socket)
                if found:
                    # Key found, terminate execution
                    raise KeyboardInterrupt

            elif action == "STOP":
                print("[*] Received STOP command from server. Exiting.")
                break

            elif action == "NO_WORK":
                print("[*] No more work available from server. Exiting.")
                break

        # Stop main loop if exit signal was processed inside buffer loop
        if command.get("action") in ["STOP", "NO_WORK"]:
            break

except KeyboardInterrupt:
    print("[*] Task complete. Closing client.")
except Exception as e:
    print(f"[-] Error: {e}")

finally:
    # 5. Close the connection
    client_socket.close()
    print("[+] Connection closed.")