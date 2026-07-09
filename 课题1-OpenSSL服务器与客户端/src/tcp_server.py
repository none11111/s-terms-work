import socket
import threading
import time

class TCPServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.connections = []
        self.lock = threading.Lock()

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            self.running = True
            print(f"[TCP Server] 监听在 {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[TCP Server] 新连接: {addr}")
                    client_socket.settimeout(30.0)
                    with self.lock:
                        self.connections.append(client_socket)
                    thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[TCP Server] 接受连接失败: {e}")
        except Exception as e:
            print(f"[TCP Server] 启动失败: {e}")

    def handle_client(self, client_socket, addr):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(f"[TCP Server] 客户端断开: {addr}")
                    break
                message = data.decode('utf-8')
                print(f"[TCP Server] 收到来自 {addr} 的数据: {message}")
                
                response = f"Server received: {message}"
                client_socket.send(response.encode('utf-8'))
                print(f"[TCP Server] 已发送响应给 {addr}")
        except socket.timeout:
            print(f"[TCP Server] 客户端超时: {addr}")
        except Exception as e:
            print(f"[TCP Server] 处理客户端 {addr} 时出错: {e}")
        finally:
            with self.lock:
                if client_socket in self.connections:
                    self.connections.remove(client_socket)
            client_socket.close()

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
        print("[TCP Server] 已停止")

if __name__ == "__main__":
    server = TCPServer(port=8888)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()