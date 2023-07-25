import socket


def is_resolvable(address):
    try:
        # 尝试解析地址
        socket.gethostbyname(address)
        return True
    except socket.error:
        return False


def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return False
        except socket.error:
            return True
