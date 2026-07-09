import socket
import time

class TCPClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.client_socket = None

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((self.host, self.port))
            print(f"[TCP Client] 已连接到 {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[TCP Client] 连接失败: {e}")
            return False

    def send_message(self, message):
        try:
            if not self.client_socket:
                print("[TCP Client] 未连接")
                return None
            self.client_socket.send(message.encode('utf-8'))
            print(f"[TCP Client] 发送数据: {message}")
            
            response = self.client_socket.recv(1024)
            if response:
                print(f"[TCP Client] 收到响应: {response.decode('utf-8')}")
                return response.decode('utf-8')
            else:
                print("[TCP Client] 连接已断开")
                return None
        except socket.timeout:
            print("[TCP Client] 超时")
            return None
        except Exception as e:
            print(f"[TCP Client] 发送失败: {e}")
            return None

    def disconnect(self):
        if self.client_socket:
            self.client_socket.close()
            print("[TCP Client] 已断开连接")

if __name__ == "__main__":
    client = TCPClient(host='localhost', port=8888)
    
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