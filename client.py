###################################################
#
#       CLIENT THAT CONNECTS VIA SOCKETS
#
###################################################

############ SERVER EXAMPLE CODE ##################
#
# import socket
#
# # 1. Create a socket object
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
# # 2. Connect to the server (localhost means this same computer)
# client_socket.connect(('127.0.0.1', 65432))
#
# try:
#   # 3. Send a message (Strings must be encoded to bytes before sending)
#   message = "Hello, Server!"
#   client_socket.sendall(message.encode('utf-8'))
#
#   # 4. Receive the reply
#   reply = client_socket.recv(1024)
#   print(f"Server replied: {reply.decode('utf-8')}")
#
# finally:
#   # 5. Close the connection
#   client_socket.close()
