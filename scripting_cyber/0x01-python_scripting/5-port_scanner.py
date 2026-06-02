#!/usr/bin/env python3
import socket

def check_port(host, port):
	try:
		tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		tcp_socket.settimeout(3)
		result = tcp_socket.connect_ex((host, port))

		if result:
			return False
		else:
			return True
	except Exception:
		return False
