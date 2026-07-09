import socket
import ssl
import threading
import os
import hashlib
import time
from datetime import datetime

SUPPORTED_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'RSA-AES256-GCM-SHA384'
]

class Logger:
    def __init__(self, log_file='../logs/server.log'):
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

    def debug(self, message):
        self.log(message, 'DEBUG')

class IntegrityChecker:
    @staticmethod
    def calculate_hash(data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_integrity(data, expected_hash):
        actual_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return actual_hash == expected_hash

class ConnectionFilter:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_certificates = set()
        self.connection_count = {}
        self.max_connections_per_ip = 10
        self.logger = Logger()

    def block_ip(self, ip_address):
        self.blocked_ips.add(ip_address)
        self.logger.warning(f"IP {ip_address} 已加入黑名单")

    def block_certificate(self, cert_fingerprint):
        self.blocked_certificates.add(cert_fingerprint)
        self.logger.warning(f"证书 {cert_fingerprint} 已加入黑名单")

    def check_connection_limit(self, ip_address):
        if ip_address not in self.connection_count:
            self.connection_count[ip_address] = 0
        
        self.connection_count[ip_address] += 1
        
        if self.connection_count[ip_address] > self.max_connections_per_ip:
            self.logger.warning(f"IP {ip_address} 超过连接限制")
            return False
        
        return True

    def is_blocked(self, ip_address, cert_fingerprint=None):
        if ip_address in self.blocked_ips:
            return True, f"IP {ip_address} 在黑名单中"
        
        if cert_fingerprint and cert_fingerprint in self.blocked_certificates:
            return True, "证书在黑名单中"
        
        if not self.check_connection_limit(ip_address):
            return True, "超过连接限制"
        
        return False, "允许连接"

class SSLServerMutual:
    def __init__(self, host='0.0.0.0', port=8444, 
                 certfile='../certs/server.crt', keyfile='../certs/server.key',
                 cafile='../certs/ca.crt', client_cert_required=True):
        self.host = host
        self.port = port
        self.certfile = os.path.join(os.path.dirname(__file__), certfile)
        self.keyfile = os.path.join(os.path.dirname(__file__), keyfile)
        self.cafile = os.path.join(os.path.dirname(__file__), cafile)
        self.client_cert_required = client_cert_required
        self.server_socket = None
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.logger = Logger()
        self.connection_filter = ConnectionFilter()
        self.cipher_suite = None

    def _create_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        try:
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            self.logger.info(f"服务器证书加载成功: {self.certfile}")
        except Exception as e:
            self.logger.error(f"服务器证书加载失败: {str(e)}")
            raise
        
        try:
            context.load_verify_locations(cafile=self.cafile)
            self.logger.info(f"CA证书加载成功: {self.cafile}")
        except Exception as e:
            self.logger.error(f"CA证书加载失败: {str(e)}")
            raise
        
        if self.client_cert_required:
            context.verify_mode = ssl.CERT_REQUIRED
            self.logger.info("已启用双向认证模式")
        else:
            context.verify_mode = ssl.CERT_OPTIONAL
            self.logger.info("使用单向认证模式")
        
        if self.cipher_suite:
            context.set_ciphers(self.cipher_suite)
            self.logger.info(f"使用指定加密套件: {self.cipher_suite}")
        else:
            context.set_ciphers(':'.join(SUPPORTED_CIPHERS))
            self.logger.info("使用默认加密套件列表")
        
        return context

    def _calculate_cert_fingerprint(self, cert):
        cert_bytes = ssl.DER_cert_to_PEM_cert(cert).encode('utf-8')
        return hashlib.sha256(cert_bytes).hexdigest()

    def _validate_certificate(self, cert):
        if not cert:
            return False, "客户端未提供证书"
        
        try:
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            
            if 'commonName' not in subject:
                return False, "客户端证书缺少CN字段"
            
            if issuer.get('commonName') != 'MyCA':
                return False, f"客户端证书签发者不是信任的CA: {issuer.get('commonName')}"
            
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            now = datetime.now()
            if now < not_before:
                return False, "客户端证书尚未生效"
            
            if now > not_after:
                return False, "客户端证书已过期"
            
            cert_fingerprint = self._calculate_cert_fingerprint(cert)
            blocked, reason = self.connection_filter.is_blocked(None, cert_fingerprint)
            if blocked:
                return False, reason
            
            return True, f"客户端证书验证通过: CN={subject['commonName']}"
        
        except Exception as e:
            return False, f"证书验证异常: {str(e)}"

    def start(self, cipher_suite=None):
        self.cipher_suite = cipher_suite
        
        try:
            context = self._create_ssl_context()
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            
            self.ssl_socket = context.wrap_socket(self.server_socket, server_side=True)
            self.running = True
            
            self.logger.info(f"SSL双向认证服务端启动，监听 {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = self.ssl_socket.accept()
                    
                    blocked, reason = self.connection_filter.is_blocked(addr[0])
                    if blocked:
                        self.logger.warning(f"[拦截] 客户端 {addr} 被拒绝: {reason}")
                        conn.send(f"ERROR: {reason}".encode())
                        conn.close()
                        continue
                    
                    thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                    
                except ssl.SSLError as e:
                    self.logger.error(f"SSL错误: {str(e)}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"接受连接失败: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"服务端启动失败: {str(e)}")

    def _handle_client(self, conn, addr):
        try:
            self.logger.info(f"新连接: {addr}")
            
            client_cert = conn.getpeercert()
            
            if self.client_cert_required:
                valid, message = self._validate_certificate(client_cert)
                if not valid:
                    self.logger.warning(f"[拦截] 客户端 {addr} 证书验证失败: {message}")
                    conn.send(f"ERROR: {message}".encode())
                    conn.close()
                    return
                self.logger.info(f"[允许] {message}")
            
            self.logger.info(f"SSL协议: {conn.version()}")
            self.logger.info(f"加密套件: {conn.cipher()}")
            
            conn.settimeout(30.0)
            
            with self.lock:
                self.connections.append(conn)
            
            self._handle_client_data(conn, addr)
            
        except ssl.SSLError as e:
            self.logger.error(f"[拦截] SSL握手失败: {str(e)}")
        except socket.timeout:
            self.logger.warning(f"客户端 {addr} 超时")
        except Exception as e:
            self.logger.error(f"处理客户端 {addr} 时出错: {str(e)}")
        finally:
            with self.lock:
                if conn in self.connections:
                    self.connections.remove(conn)
            conn.close()
            self.logger.info(f"客户端 {addr} 连接断开")

    def _handle_client_data(self, conn, addr):
        while True:
            try:
                data = conn.recv(2048)
                if not data:
                    break
                
                try:
                    message = data.decode('utf-8')
                    parts = message.split('|HASH:')
                    
                    if len(parts) == 2:
                        content = parts[0]
                        received_hash = parts[1]
                        
                        if IntegrityChecker.verify_integrity(content, received_hash):
                            self.logger.info(f"收到来自 {addr} 的加密数据: {content} (完整性校验通过)")
                        else:
                            self.logger.warning(f"来自 {addr} 的数据完整性校验失败！数据可能已被篡改！")
                            response = "ERROR: Data integrity check failed"
                            response_hash = IntegrityChecker.calculate_hash(response)
                            conn.send(f"{response}|HASH:{response_hash}".encode())
                            continue
                    else:
                        content = message
                        self.logger.info(f"收到来自 {addr} 的加密数据: {content}")
                
                except Exception:
                    content = str(data)
                    self.logger.info(f"收到来自 {addr} 的二进制数据")
                
                response = f"SSL Mutual Server received: {content}"
                response_hash = IntegrityChecker.calculate_hash(response)
                conn.send(f"{response}|HASH:{response_hash}".encode())
                self.logger.info(f"已发送加密响应给 {addr}")
                
            except socket.timeout:
                break
            except Exception as e:
                self.logger.error(f"数据处理失败: {str(e)}")
                break

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
        self.logger.info("SSL双向认证服务端已停止")

if __name__ == "__main__":
    server = SSLServerMutual(port=8444)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()