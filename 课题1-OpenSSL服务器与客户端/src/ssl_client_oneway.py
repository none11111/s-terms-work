import socket
import ssl
import os

class SSLClientOneWay:
    def __init__(self, host='localhost', port=8443, cafile='../certs/ca.crt'):
        self.host = host
        self.port = port
        self.cafile = os.path.join(os.path.dirname(__file__), cafile)
        self.ssl_socket = None

    def connect(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=self.cafile)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            self.ssl_socket = context.wrap_socket(sock, server_hostname=self.host)
            self.ssl_socket.connect((self.host, self.port))
            
            cert = self.ssl_socket.getpeercert()
            print(f"[SSL Client (One-Way)] 已连接到 {self.host}:{self.port}")
            print(f"[SSL Client (One-Way)] SSL协议: {self.ssl_socket.version()}")
            print(f"[SSL Client (One-Way)] 加密套件: {self.ssl_socket.cipher()}")
            print(f"[SSL Client (One-Way)] 服务器证书CN: {cert['subject'][0][0][1]}")
            return True
        except ssl.SSLCertVerificationError as e:
            print(f"[SSL Client (One-Way)] 证书验证失败: {e}")
            return False
        except Exception as e:
            print(f"[SSL Client (One-Way)] 连接失败: {e}")
            return False

    def send_message(self, message):
        try:
            if not self.ssl_socket:
                print("[SSL Client (One-Way)] 未连接")
                return None
            self.ssl_socket.send(message.encode('utf-8'))
            print(f"[SSL Client (One-Way)] 发送加密数据: {message}")
            
            response = self.ssl_socket.recv(1024)
            if response:
                print(f"[SSL Client (One-Way)] 收到加密响应: {response.decode('utf-8')}")
                return response.decode('utf-8')
            else:
                print("[SSL Client (One-Way)] 连接已断开")
                return None
        except Exception as e:
            print(f"[SSL Client (One-Way)] 发送失败: {e}")
            return None

    def disconnect(self):
        if self.ssl_socket:
            self.ssl_socket.close()
            print("[SSL Client (One-Way)] 已断开连接")

if __name__ == "__main__":
    client = SSLClientOneWay(host='localhost', port=8443)
    
    if client.connect():
        try:
            while True:
                message = input("请输入要发送的消息 (输入 quit 退出): ")
                if message.lower() == 'quit':
                    break
                if message.strip():
                    client.send_message(message)
        except KeyboardInterrupt:
            pass
        finally:
            client.disconnect()