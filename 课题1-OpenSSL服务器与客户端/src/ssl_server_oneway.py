import socket
import ssl
import threading
import os

class SSLServerOneWay:
    def __init__(self, host='0.0.0.0', port=8443, certfile='../certs/server.crt', keyfile='../certs/server.key'):
        self.host = host
        self.port = port
        self.certfile = os.path.join(os.path.dirname(__file__), certfile)
        self.keyfile = os.path.join(os.path.dirname(__file__), keyfile)
        self.server_socket = None
        self.running = False
        self.connections = []
        self.lock = threading.Lock()

    def start(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            
            self.ssl_socket = context.wrap_socket(self.server_socket, server_side=True)
            self.running = True
            
            print(f"[SSL Server (One-Way)] 监听在 {self.host}:{self.port}")
            print(f"[SSL Server (One-Way)] 证书: {self.certfile}")
            print(f"[SSL Server (One-Way)] 私钥: {self.keyfile}")
            
            while self.running:
                try:
                    conn, addr = self.ssl_socket.accept()
                    print(f"[SSL Server (One-Way)] 新连接: {addr}")
                    print(f"[SSL Server (One-Way)] SSL协议: {conn.version()}")
                    print(f"[SSL Server (One-Way)] 加密套件: {conn.cipher()}")
                    
                    conn.settimeout(30.0)
                    with self.lock:
                        self.connections.append(conn)
                    
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                except ssl.SSLError as e:
                    print(f"[SSL Server (One-Way)] SSL错误: {e}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[SSL Server (One-Way)] 接受连接失败: {e}")
        except Exception as e:
            print(f"[SSL Server (One-Way)] 启动失败: {e}")

    def handle_client(self, conn, addr):
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    print(f"[SSL Server (One-Way)] 客户端断开: {addr}")
                    break
                message = data.decode('utf-8')
                print(f"[SSL Server (One-Way)] 收到来自 {addr} 的加密数据: {message}")
                
                response = f"SSL Server received: {message}"
                conn.send(response.encode('utf-8'))
                print(f"[SSL Server (One-Way)] 已发送加密响应给 {addr}")
        except socket.timeout:
            print(f"[SSL Server (One-Way)] 客户端超时: {addr}")
        except Exception as e:
            print(f"[SSL Server (One-Way)] 处理客户端 {addr} 时出错: {e}")
        finally:
            with self.lock:
                if conn in self.connections:
                    self.connections.remove(conn)
            conn.close()

    def stop(self):
        self.running = False
        with self.lock:
            for conn in self.connections:
                try:
                    conn.close()
                except:
                    pass
        if self.server_socket:
            self.server_socket.close()
        print("[SSL Server (One-Way)] 已停止")

if __name__ == "__main__":
    server = SSLServerOneWay(port=8443)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()