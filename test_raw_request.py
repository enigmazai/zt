import socket
s = socket.socket()
s.connect(('127.0.0.1', 8000))
req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
s.send(req)
resp = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
s.close()
print(resp.decode(errors='replace'))
