import socket
import json
import hmac
import hashlib
import time

# Configuration settings
SERVER_IP = '127.0.0.1'
SERVER_PORT = 65433

# Toggle between Standard HMAC-MD5 (True) vs RFC 2082 Keyed-MD5 (False)
USE_STANDARD_HMAC = False

CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"

def index_to_candidate(index, length):
    base = len(CHARSET)
    chars = ["0"] * length
    for i in range(length - 1, -1, -1):
        chars[i] = CHARSET[index % base]
        index //= base
    return "".join(chars)

def compute_digest(raw_candidate, payload_bytes):
    """
    Computes digest using raw candidate key (e.g., '00335b') 
    padded with NULL bytes (\x00) to 16 bytes.
    """
    key_ascii_bytes = raw_candidate.encode('utf-8')
    
    # Pad candidate key to exactly 16 bytes using binary NULL bytes (\x00)
    padded_key_bytes = key_ascii_bytes.ljust(16, b'\x00')

    if USE_STANDARD_HMAC:
        # Standard HMAC-MD5 using padded 16-byte key
        return hmac.new(padded_key_bytes, payload_bytes, hashlib.md5).hexdigest()
    else:
        # RFC 2082 Keyed-MD5: MD5(Payload + 16-byte Padded Key)
        md5_obj = hashlib.md5()
        md5_obj.update(payload_bytes)
        md5_obj.update(padded_key_bytes)
        return md5_obj.hexdigest()

def process_work_assignment(command, client_socket):
    """Processes an ASSIGN_WORK command and executes the brute-force search."""
    start_int = int(command["start_hex"], 16)
    end_int = int(command["end_hex"], 16)
    target_hmac = command["target_hmac"]
    payload_bytes = bytes.fromhex(command["payload_hex"])
    
    # Read dynamic key length provided by server.py (defaults to 6 if missing)
    key_length = command.get("key_length", 6)

    print(f"Testing range {hex(start_int)} to {hex(end_int)} (Key length: {key_length})")

    start_time = time.time()
    found_candidate = None

    for current_int in range(start_int, end_int + 1):
        raw_candidate = index_to_candidate(current_int, key_length)
        calculated_digest = compute_digest(raw_candidate, payload_bytes)

        if calculated_digest.lower() == target_hmac.lower():
            found_candidate = raw_candidate
            tested = current_int - start_int + 1
            break
    else:
        tested = end_int - start_int + 1

    elapsed = time.time() - start_time
    rate = tested / elapsed if elapsed > 0 else tested

    print(f"Block took {elapsed:.2f}s, {tested} hashes, {rate:.0f} hashes/sec")

    block_msg = json.dumps({
        "action": "BLOCK_DONE",
        "elapsed": elapsed,
        "count": tested,
        "rate": rate,
    }) + "\n"
    client_socket.sendall(block_msg.encode('utf-8'))

    if found_candidate is not None:
        print(f"Key found! Candidate: '{found_candidate}'")
        found_msg = json.dumps({
            "action": "KEY_FOUND",
            "key": found_candidate
        }) + "\n"
        client_socket.sendall(found_msg.encode('utf-8'))
        return True

    print("Range completed without matches.")
    return False

def main():
    # 1. Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 2. Connect to the server
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")

    buffer = ""
    should_exit = False

    try:
        while not should_exit:
            # 3. Send work request to server
            request_msg = json.dumps({"action": "REQUEST_WORK"}) + "\n"
            client_socket.sendall(request_msg.encode('utf-8'))

            # 4. Receive reply from server
            reply = client_socket.recv(4096)
            if not reply:
                print("Connection closed by server.")
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
                        should_exit = True
                        break

                elif action == "STOP":
                    print("Received STOP command from server. Exiting.")
                    should_exit = True
                    break

                elif action == "NO_WORK":
                    print("No more work available from server. Exiting.")
                    should_exit = True
                    break

    except KeyboardInterrupt:
        print("Task interrupted by user. Closing client.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # 5. Close the connection
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()