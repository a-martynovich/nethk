import socket

HOST = '127.0.0.1'      # Symbolic name meaning the local host
PORT = 80            # Arbitrary non-privileged port

while 1:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((HOST, PORT))
	s.listen(1)
	conn, addr = s.accept()

	print 'Connected by', addr

	while 1:
	        data = conn.recv(1024)
	        if not data:
	                break
	        #conn.send(data)
	        print data

	conn.close()