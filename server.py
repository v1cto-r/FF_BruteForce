###################################################
#
#    SERVER THAT CONNECTS VIA SOCKETS AND QUEUE
#
###################################################

import socket
import json
import heapq
import threading

HOST = '127.0.0.1'
PORT = 65432
KEY_LENGTH = 6          # zero-padded hex digits per candidate key, matches client.py default
BLOCK_SIZE = 65536      # how many keys go out per assigned block

# --- shared state (reset in start_server, guarded by the locks below) ---
queue_lock = threading.Lock()
found_lock = threading.Lock()

heap = []               # heapq of (priority, block) for requeued blocks only
requeue_counter = -1    # decremented on every requeue so latest failure sorts first
next_start = 0          # cursor into untouched keyspace
next_id = 0
total_keyspace = 16 ** KEY_LENGTH
found_key = None


def get_block():
    """Pop the next block to hand out: requeued blocks first, then fresh ones."""
    global next_start, next_id
    with queue_lock:
        if heap:
            _, block = heapq.heappop(heap)
            return block
        if next_start >= total_keyspace:
            return None
        start = next_start
        end = min(next_start + BLOCK_SIZE, total_keyspace)
        block = {"id": next_id, "start": start, "end": end}
        next_start = end
        next_id += 1
        return block


def requeue_block(block):
    """Put a block back at the front of the line (client disconnected mid-block)."""
    global requeue_counter
    with queue_lock:
        heapq.heappush(heap, (requeue_counter, block))
        requeue_counter -= 1


def set_found_key(key):
    global found_key
    with found_lock:
        if found_key is None:
            found_key = key
            return True
        return False


def is_found():
    with found_lock:
        return found_key is not None


def send_json(conn, payload):
    conn.sendall((json.dumps(payload) + "\n").encode('utf-8'))


def handle_client(conn, addr, target_hmac, payload_hex):
    print(f"[+] Connected by {addr}")
    buffer = ""
    current_block = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode('utf-8')

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                msg = json.loads(line)
                action = msg.get("action")

                if action == "REQUEST_WORK":
                    if current_block is not None:
                        # a fresh request with no KEY_FOUND means the previous
                        # block was exhausted without a match
                        current_block = None

                    if is_found():
                        send_json(conn, {"action": "STOP"})
                        return

                    block = get_block()
                    if block is None:
                        send_json(conn, {"action": "NO_WORK"})
                        return

                    current_block = block
                    send_json(conn, {
                        "action": "ASSIGN_WORK",
                        "start_hex": format(block["start"], f"0{KEY_LENGTH}x"),
                        "end_hex": format(block["end"] - 1, f"0{KEY_LENGTH}x"),
                        "target_hmac": target_hmac,
                        "payload_hex": payload_hex,
                        "key_length": KEY_LENGTH,
                    })

                elif action == "KEY_FOUND":
                    key = msg.get("key")
                    if set_found_key(key):
                        print(f"[!] Key found by {addr}: {key}")
                    current_block = None
                    return

                # unknown actions are ignored, matching the client's own behavior

    except (ConnectionError, OSError) as e:
        print(f"[-] Connection with {addr} lost: {e}")
    finally:
        if current_block is not None:
            requeue_block(current_block)
        conn.close()
        print(f"[-] Connection with {addr} closed.")


def start_server(target_hmac, payload_hex):
    """Reset job state and run the accept loop until the process is killed."""
    global heap, requeue_counter, next_start, next_id, found_key
    heap = []
    requeue_counter = -1
    next_start = 0
    next_id = 0
    found_key = None

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT} (key_length={KEY_LENGTH}, block_size={BLOCK_SIZE})")

    try:
        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, target_hmac, payload_hex),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("[*] Server shutting down.")
    finally:
        server_socket.close()
