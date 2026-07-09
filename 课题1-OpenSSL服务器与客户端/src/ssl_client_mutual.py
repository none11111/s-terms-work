import socket
import ssl
import os
import hashlib
import time
from datetime import datetime

class Logger:
    def __init__(self, log_file='../logs/client.log'):
        self.log_file = os.path.join(os.path.dirname(__file__), log_file)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log(self, message, level='INFO'):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        print(f"[{timestamp}] [{level}] {message}")

    def info(self, message):
        self.log(message, 'INFO')

    def warning(self, message):
        self.log(message, 'WARNING')

    def error(self, message):
        self.log(message, 'ERROR')

class IntegrityChecker:
    @staticmethod
    def calculate_hash(data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_integrity(data, expected_hash):
        actual_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return actual_hash == expected_hash

class SSLClientMutual:
    def __init__(self, host='localhost', port=8444,
                 certfile='../certs/client.crt', keyfile='../certs/client.key',
                 cafile='../certs/ca.crt'):
        self.host = host
        self.port = port
        self.certfile = os.path.join(os.path.dirname(__file__), certfile)
        self.keyfile = os.path.join(os.path.dirname(__file__), keyfile)
        self.cafile = os.path.join(os.path.dirname(__file__), cafile)
        self.ssl_socket = None
        self.logger = Logger()

    def _create_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        try:
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            self.logger.info(f"客户端证书加载成功: {self.certfile}")
        except Exception as e:
            self.logger.error(f"客户端证书加载失败: {str(e)}")
            raise
        
        try:
            context.load_verify_locations(cafile=self.cafile)
            self.logger.info(f"CA证书加载成功: {self.cafile}")
        except Exception as e:
            self.logger.error(f"CA证书加载失败: {str(e)}")
            raise
        
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        
        self.logger.info("已配置双向认证模式")
        
        return context

    def _validate_server_certificate(self, cert):
        if not cert:
            return False, "服务端未提供证书"
        
        try:
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            
            if 'commonName' not in subject:
                return False, "服务端证书缺少CN字段"
            
            if subject['commonName'] != 'localhost':
                return False, f"服务端证书CN不匹配: {subject['commonName']}"
            
            if issuer.get('commonName') != 'MyCA':
                return False, f"服务端证书签发者不是信任的CA: {issuer.get('commonName')}"
            
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            now = datetime.now()
            if now < not_before:
                return False, "服务端证书尚未生效"
            
            if now > not_after:
                return False, "服务端证书已过期"
            
            return True, f"服务端证书验证通过: CN={subject['commonName']}"
        
        except Exception as e:
            return False, f"证书验证异常: {str(e)}"

    def connect(self):
        try:
            context = self._create_ssl_context()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            
            self.ssl_socket = context.wrap_socket(sock, server_hostname=self.host)
            self.ssl_socket.connect((self.host, self.port))
            
            server_cert = self.ssl_socket.getpeercert()
            
            valid, message = self._validate_server_certificate(server_cert)
            if valid:
                self.logger.info(f"[允许] {message}")
            else:
                self.logger.warning(f"[警告] {message}")
            
            self.logger.info(f"已连接到 {self.host}:{self.port}")
            self.logger.info(f"SSL协议: {self.ssl_socket.version()}")
            self.logger.info(f"加密套件: {self.ssl_socket.cipher()}")
            
            return True
            
        except ssl.SSLCertVerificationError as e:
            self.logger.error(f"证书验证失败: {str(e)}")
            return False
        except ConnectionRefusedError:
            self.logger.error(f"连接被拒绝，请检查服务端是否启动")
            return False
        except socket.timeout:
            self.logger.error("连接超时")
            return False
        except Exception as e:
            self.logger.error(f"连接失败: {str(e)}")
            return False

    def send_message(self, message):
        try:
            if not self.ssl_socket:
                self.logger.error("未连接到服务端")
                return None
            
            data_hash = IntegrityChecker.calculate_hash(message)
            message_with_hash = f"{message}|HASH:{data_hash}"
            
            self.ssl_socket.send(message_with_hash.encode('utf-8'))
            self.logger.info(f"发送加密数据: {message} (哈希: {data_hash[:16]}...)")
            
            response = self.ssl_socket.recv(2048)
            if response:
                try:
                    response_str = response.decode('utf-8')
                    parts = response_str.split('|HASH:')
                    
                    if len(parts) == 2:
                        content = parts[0]
                        received_hash = parts[1]
                        
                        if IntegrityChecker.verify_integrity(content, received_hash):
                            self.logger.info(f"收到加密响应: {content} (完整性校验通过)")
                        else:
                            self.logger.warning(f"响应完整性校验失败！")
                    else:
                        self.logger.info(f"收到加密响应: {response_str}")
                    
                    return response_str
                except Exception:
                    self.logger.info(f"收到二进制响应")
                    return str(response)
            else:
                self.logger.warning("连接已断开")
                return None
                
        except socket.timeout:
            self.logger.error("发送超时")
            return None
        except Exception as e:
            self.logger.error(f"发送失败: {str(e)}")
            return None

    def disconnect(self):
        if self.ssl_socket:
            self.ssl_socket.close()
            self.logger.info("已断开连接")

if __name__ == "__main__":
    client = SSLClientMutual(host='localhost', port=8444)
    
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