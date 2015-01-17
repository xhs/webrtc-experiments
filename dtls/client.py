# -*- coding: utf-8 -*-

import ssl
from socket import socket, AF_INET, SOCK_DGRAM
from dtls import do_patch

do_patch()

host = '127.0.0.1'
port = 60080

s = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM))
s.connect((host, port))

s.sendall('hello')
data = s.recv(1024)
s.close()
print 'received', data
