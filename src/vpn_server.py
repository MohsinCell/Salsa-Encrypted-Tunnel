import socket
import threading
import time
import logging
import json
import sys
import os
import uuid
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from deimos_wrapper import DeimosCipher
from tunnel_manager import TunnelManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ClientSession:
    socket: socket.socket
    client_id: str
    username: str
    cipher: DeimosCipher
    tunnel_manager: TunnelManager
    last_activity: float
    authenticated: bool = False
    session_key: Optional[bytes] = None

class VPNServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.clients: Dict[str, ClientSession] = {}
        self.client_lock = threading.Lock()
        self.config = {
            "buffer_size": 4096,
            "max_clients": 100,
            "client_timeout": 300,
            "cleanup_interval": 60,
            "tunnel_subnet": "10.0.0.0/24",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "timeout": 30,
            "keepalive_interval": 10,
            "max_retries": 3
        }
        self.users = {
            "testuser": "testpass",
            "admin": "admin123"
        }
        self.dll_path = self._find_dll_path()
    
    def _find_dll_path(self) -> Optional[str]:
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'src', 'deimos_cipher.dll'),
            os.path.join(os.path.dirname(__file__), 'deimos_cipher.dll'),
            r"C:/My Projects/Encrypted VPN Prototype/src/deimos_cipher.dll",
            "./deimos_cipher.dll",
            "../src/deimos_cipher.dll"
        ]
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found DLL at: {path}")
                return path
        logger.warning("DLL not found")
        return None
    
    def start_server(self) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.config["max_clients"])
            self.running = True
            logger.info(f"VPN Server started on {self.host}:{self.port}")
            self.start_client_cleanup()
            return True
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False
    
    def stop_server(self):
        self.running = False
        with self.client_lock:
            for client_id in list(self.clients.keys()):
                self.disconnect_client(client_id)
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("VPN Server stopped")
    
    def accept_connections(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def handle_client(self, client_socket: socket.socket, client_address):
        client_id = None
        try:
            client_session = self.perform_handshake(client_socket, client_address)
            if not client_session:
                client_socket.close()
                return
            client_id = client_session.client_id
            with self.client_lock:
                self.clients[client_id] = client_session
            logger.info(f"Client {client_id} ({client_session.username}) authenticated")
            self.handle_client_messages(client_session)
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if client_id:
                self.disconnect_client(client_id)
    
    def perform_handshake(self, client_socket: socket.socket, client_address) -> Optional[ClientSession]:
        try:
            client_socket.settimeout(self.config["timeout"])
            request_length_bytes = client_socket.recv(4)
            if len(request_length_bytes) != 4:
                logger.error("Invalid handshake request length")
                return None
            request_length = int.from_bytes(request_length_bytes, 'big')
            if request_length > 10000:
                logger.error("Handshake request too large")
                return None
            request_data = client_socket.recv(request_length)
            if len(request_data) != request_length:
                logger.error("Incomplete handshake request")
                return None
            request = json.loads(request_data.decode('utf-8'))
            if request.get("type") != "handshake":
                self.send_handshake_response(client_socket, False, "Invalid handshake type")
                return None
            username = request.get("username")
            password = request.get("password")
            if not username or not password:
                self.send_handshake_response(client_socket, False, "Missing credentials")
                return None
            if not self.authenticate_user(username, password):
                self.send_handshake_response(client_socket, False, "Authentication failed")
                return None
            session_key = self.generate_session_key()
            try:
                cipher = DeimosCipher(dll_path=self.dll_path) if self.dll_path else DeimosCipher()
                if hasattr(cipher, 'init_cipher'):
                    cipher.init_cipher(session_key)
                elif hasattr(cipher, 'set_key'):
                    cipher.set_key(session_key)
            except Exception as e:
                logger.error(f"Failed to initialize cipher: {e}")
                self.send_handshake_response(client_socket, False, "Encryption initialization failed")
                return None
            client_id = str(uuid.uuid4())
            try:
                tunnel_manager = TunnelManager(
                    is_server=True,
                    config=self.config
                )
            except Exception as e:
                logger.error(f"Failed to create tunnel manager: {e}")
                self.send_handshake_response(client_socket, False, "Tunnel initialization failed")
                return None
            client_session = ClientSession(
                socket=client_socket,
                client_id=client_id,
                username=username,
                cipher=cipher,
                tunnel_manager=tunnel_manager,
                last_activity=time.time(),
                authenticated=True,
                session_key=session_key
            )
            self.send_handshake_response(client_socket, True, "Authentication successful", client_id, session_key)
            try:
                tunnel_manager.start()
            except Exception as e:
                logger.error(f"Failed to start tunnel manager: {e}")
                return None
            self.send_tunnel_config(client_session)
            client_socket.settimeout(None)
            return client_session
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in handshake from {client_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Handshake error with {client_address}: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> bool:
        return self.users.get(username) == password
    
    def generate_session_key(self) -> bytes:
        import secrets
        return secrets.token_bytes(32)
    
    def send_handshake_response(self, client_socket: socket.socket, success: bool, message: str, 
                               client_id: str = None, session_key: bytes = None):
        response = {
            "status": "success" if success else "error",
            "message": message,
            "server_version": "1.0"
        }
        if success and client_id:
            response["client_id"] = client_id
            if session_key:
                response["session_key"] = base64.b64encode(session_key).decode('utf-8')
        response_data = json.dumps(response).encode('utf-8')
        try:
            client_socket.send(len(response_data).to_bytes(4, 'big'))
            client_socket.send(response_data)
        except Exception as e:
            logger.error(f"Failed to send handshake response: {e}")
    
    def send_tunnel_config(self, client_session: ClientSession):
        config = {
            "type": "tunnel_config",
            "config": {
                "subnet": self.config["tunnel_subnet"],
                "dns_servers": self.config["dns_servers"],
                "mtu": 1500,
                "buffer_size": self.config["buffer_size"],
                "timeout": self.config["timeout"]
            }
        }
        config_data = json.dumps(config).encode('utf-8')
        self.send_encrypted_to_client(client_session, config_data)
    
    def handle_client_messages(self, client_session: ClientSession):
        while self.running and client_session.authenticated:
            try:
                data = self.receive_encrypted_from_client(client_session)
                if data:
                    client_session.last_activity = time.time()
                    try:
                        message = json.loads(data.decode('utf-8'))
                        self.process_client_message(client_session, message)
                    except json.JSONDecodeError:
                        if client_session.tunnel_manager:
                            try:
                                client_session.tunnel_manager.handle_incoming_data(data)
                            except Exception as e:
                                logger.error(f"Tunnel manager error for {client_session.client_id}: {e}")
                else:
                    logger.info(f"Client {client_session.client_id} disconnected")
                    break
            except Exception as e:
                logger.error(f"Error handling client {client_session.client_id}: {e}")
                break
    
    def process_client_message(self, client_session: ClientSession, message: Dict[str, Any]):
        msg_type = message.get("type")
        if msg_type == "keepalive":
            response = {"type": "keepalive_response", "timestamp": time.time()}
            response_data = json.dumps(response).encode('utf-8')
            self.send_encrypted_to_client(client_session, response_data)
        elif msg_type == "disconnect":
            logger.info(f"Client {client_session.client_id} requested disconnect")
            client_session.authenticated = False
        else:
            logger.warning(f"Unknown message type from {client_session.client_id}: {msg_type}")
    
    def send_encrypted_to_client(self, client_session: ClientSession, data: bytes) -> bool:
        try:
            session_key_str = base64.b64encode(client_session.session_key).decode('utf-8')
            encrypted_data = client_session.cipher.encrypt_bytes(data, session_key_str)
            length_bytes = len(encrypted_data).to_bytes(4, 'big')
            client_session.socket.send(length_bytes)
            client_session.socket.send(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Failed to send data to client {client_session.client_id}: {e}")
            return False
    
    def receive_encrypted_from_client(self, client_session: ClientSession) -> Optional[bytes]:
        try:
            length_bytes = client_session.socket.recv(4)
            if len(length_bytes) != 4:
                return None
            data_length = int.from_bytes(length_bytes, 'big')
            if data_length > 1000000:
                logger.error(f"Data length too large: {data_length}")
                return None
            encrypted_data = b''
            while len(encrypted_data) < data_length:
                remaining = data_length - len(encrypted_data)
                chunk = client_session.socket.recv(min(remaining, self.config["buffer_size"]))
                if not chunk:
                    break
                encrypted_data += chunk
            if len(encrypted_data) != data_length:
                logger.error(f"Incomplete data received: expected {data_length}, got {len(encrypted_data)}")
                return None
            session_key_str = base64.b64encode(client_session.session_key).decode('utf-8')
            decrypted_data = client_session.cipher.decrypt_bytes(encrypted_data, session_key_str)
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to receive data from client {client_session.client_id}: {e}")
            return None
    
    def send_to_client(self, client_id: str, data: bytes) -> bool:
        with self.client_lock:
            client_session = self.clients.get(client_id)
            if client_session:
                return self.send_encrypted_to_client(client_session, data)
        return False
    
    def disconnect_client(self, client_id: str):
        with self.client_lock:
            client_session = self.clients.pop(client_id, None)
            if client_session:
                try:
                    if client_session.tunnel_manager:
                        client_session.tunnel_manager.stop()
                    client_session.socket.close()
                except Exception as e:
                    logger.error(f"Error disconnecting client {client_id}: {e}")
                logger.info(f"Client {client_id} disconnected")
    
    def start_client_cleanup(self):
        def cleanup_worker():
            while self.running:
                current_time = time.time()
                timeout_clients = []
                with self.client_lock:
                    for client_id, client_session in self.clients.items():
                        if current_time - client_session.last_activity > self.config["client_timeout"]:
                            timeout_clients.append(client_id)
                for client_id in timeout_clients:
                    logger.info(f"Client {client_id} timed out")
                    self.disconnect_client(client_id)
                time.sleep(self.config["cleanup_interval"])
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def get_server_stats(self) -> Dict[str, Any]:
        with self.client_lock:
            return {
                "running": self.running,
                "active_clients": len(self.clients),
                "max_clients": self.config["max_clients"],
                "dll_path": self.dll_path,
                "clients": [
                    {
                        "id": session.client_id,
                        "username": session.username,
                        "last_activity": session.last_activity,
                        "tunnel_active": session.tunnel_manager.is_active() if session.tunnel_manager else False
                    }
                    for session in self.clients.values()
                ]
            }
    
    def broadcast_message(self, message: Dict[str, Any], exclude_client: str = None):
        message_data = json.dumps(message).encode('utf-8')
        with self.client_lock:
            for client_id, client_session in self.clients.items():
                if client_id != exclude_client:
                    self.send_encrypted_to_client(client_session, message_data)

def main():
    server = VPNServer()
    try:
        if server.start_server():
            print(f"VPN Server started on {server.host}:{server.port}")
            print(f"DLL Path: {server.dll_path}")
            print("Press Ctrl+C to stop the server")
            server.accept_connections()
        else:
            print("Failed to start VPN server")
    except KeyboardInterrupt:
        print("\nShutting down VPN server...")
    finally:
        server.stop_server()

if __name__ == "__main__":
    main()
