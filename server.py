###################################################
#
#    SERVER THAT CONNECTS VIA SOCKETS AND QUEUE
#
###################################################

############ SERVER EXAMPLE CODE ##################

# import socket
#
# # 1. Create a socket object (AF_INET = IPv4, SOCK_STREAM = TCP)
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
# # 2. Allow immediate reuse of the port (prevents 'Address already in use' errors)
# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#
# # 3. Bind the socket to the host and port
# # '' means it will listen on all available network interfaces
# server_socket.bind(('', 65432))
#
# # 4. Listen for connections (backlog queue size of 5)
# server_socket.listen(5)
# print("Server is listening on port 65432...")
#
# try:
#   while True:
#     # 5. Accept an incoming connection (blocks until a client connects)
#     client_socket, client_address = server_socket.accept()
#     print(f"Connected by {client_address}")
#
#     try:
#       while True:
#         # 6. Receive data (up to 1024 bytes)
#         data = client_socket.recv(1024)
#         if not data:
#           break  # Client disconnected
#
#         print(f"Received: {data.decode('utf-8')}")
#
#         # 7. Echo the data back to the client
#         client_socket.sendall(data)
#     except ConnectionError:
#       print("Client connection lost unexpectedly.")
#     finally:
#       # 8. Clean up the client socket
#       client_socket.close()
#       print(f"Connection with {client_address} closed.")
# finally:
#   server_socket.close()
