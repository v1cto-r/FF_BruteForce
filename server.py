import socket
import json
import heapq
import subprocess
import threading
import time

MININET_CONTAINER = "ff-bruteforce-lab"
TOPO_PATH_IN_CONTAINER = "/data/FF_BruteForce/topo.py"

HOST = '0.0.0.0'
PORT = 65433
KEY_LENGTH = 5          # zero-padded hex digits per candidate key, matches client.py default
BLOCK_SIZE = 16_777_216      # how many keys go out per assigned block

# shared state (reset in start_server, guarded by the locks below)
# locks implemented cause there are multiple threads
# Could happen that 2 threads ask for blocks at the same time, without a lock a race condition will happen
queue_lock = threading.Lock()
found_lock = threading.Lock()
rates_lock = threading.Lock()

heap = []               # heapq of (priority, block) for requeued blocks only
requeue_counter = -1    # decremented on every requeue so latest failure sorts first
next_start = 0          # cursor into untouched keyspace
next_id = 0
total_keyspace = 36 ** KEY_LENGTH
found_key = None
start_time = None
client_rates = {}


def get_block():
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


def set_client_rate(addr, rate):
    with rates_lock:
        client_rates[addr] = rate
        return sum(client_rates.values())


def drop_client_rate(addr):
    with rates_lock:
        client_rates.pop(addr, None)


def handle_client(conn, addr, target_hmac, payload_hex):
    print(f"Connected by {addr}")
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

                elif action == "BLOCK_DONE":
                    elapsed = msg.get("elapsed")
                    count = msg.get("count")
                    rate = msg.get("rate")
                    total_rate = set_client_rate(addr, rate)
                    print(f"Client {addr} block: {count} hashes in {elapsed:.2f}s, {rate:.0f} hashes/sec")
                    print(f"Total across all clients: {total_rate:.0f} hashes/sec")

                elif action == "KEY_FOUND":
                    key = msg.get("key")
                    if set_found_key(key):
                        print(f"Key found by {addr}: {key}")
                    current_block = None
                    return

    except (ConnectionError, OSError) as e:
        print(f"Connection with {addr} lost: {e}")
    finally:
        if current_block is not None:
            requeue_block(current_block)
        drop_client_rate(addr)
        conn.close()
        print(f"Connection with {addr} closed.")


def start_server(target_hmac, payload_hex):
    global heap, requeue_counter, next_start, next_id, found_key, start_time, client_rates
    heap = []
    requeue_counter = -1
    next_start = 0
    next_id = 0
    found_key = None
    client_rates = {}
    start_time = time.time()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    server_socket.settimeout(10)
    print(f"Server listening on {HOST}:{PORT} (key_length={KEY_LENGTH}, block_size={BLOCK_SIZE})")

    try:
        while not is_found():
            try:
                conn, addr = server_socket.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, target_hmac, payload_hex),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

    total_elapsed = time.time() - start_time
    print(f"Total cracking time: {total_elapsed:.2f}s")

    return found_key


def inject_via_mininet(key):
    # This one here runs the python 3 script with the cracked password
    
    cmd = ["docker", "exec", MININET_CONTAINER, "python3", TOPO_PATH_IN_CONTAINER, "--key", key]
    print(f"Injecting cracked key via {MININET_CONTAINER}: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
