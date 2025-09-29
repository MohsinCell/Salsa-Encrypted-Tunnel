import socket
import threading
import time
import logging
import json
import sys
import os
import base64
from typing import Optional, Dict, Any

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from deimos_wrapper import DeimosCipher
from tunnel_manager import TunnelManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VPNClient:
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 8080):
        self.server_host = server_host
        self.server_port = server_port
        self.socket: Optional[socket.socket] = None
        self.cipher: Optional[DeimosCipher] = None
        self.tunnel_manager: Optional[TunnelManager] = None
        self.running = False
        self.authenticated = False
        self.session_key: Optional[bytes] = None
        self.client_id: Optional[str] = None

        self.config = {
            "buffer_size": 4096,
            "timeout": 30,
            "keepalive_interval": 10,
            "max_retries": 3
        }

        self.dll_path = self._find_dll_path()

    def _find_dll_path(self) -> Optional[str]:
        paths = [
            os.path.join(os.path.dirname(__file__), '..', 'src', 'deimos_cipher.dll'),
            os.path.join(os.path.dirname(__file__), 'deimos_cipher.dll'),
            r"C:/My Projects/Encrypted VPN Prototype/src/deimos_cipher.dll",
            "./deimos_cipher.dll",
            "../src/deimos_cipher.dll"
        ]
        for path in paths:
            if os.path.exists(path):
                logger.info(f"Found DLL at: {path}")
                return path
        logger.warning("DLL not found")
        return None

    def connect_to_server(self) -> bool:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.config["timeout"])
            self.socket.connect((self.server_host, self.server_port))
            logger.info(f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except socket.error as e:
            logger.error(f"Failed to connect: {e}")
            return False

    def perform_handshake(self, username: str, password: str) -> bool:
        try:
            handshake_data = {
                "type": "handshake",
                "username": username,
                "password": password,
                "client_version": "1.0",
                "supported_ciphers": ["deimos"]
            }
            message = json.dumps(handshake_data).encode('utf-8')
            self.socket.send(len(message).to_bytes(4, 'big'))
            self.socket.send(message)

            response_length_bytes = self.socket.recv(4)
            if len(response_length_bytes) != 4:
                logger.error("Bad handshake response length")
                return False

            response_length = int.from_bytes(response_length_bytes, 'big')
            if response_length > 10000:
                logger.error("Handshake response too large")
                return False

            response_data = self.socket.recv(response_length)
            if len(response_data) != response_length:
                logger.error("Incomplete handshake response")
                return False

            response = json.loads(response_data.decode('utf-8'))

            if response.get("status") == "success":
                self.authenticated = True
                self.client_id = response.get("client_id")
                session_key_b64 = response.get("session_key")
                if not session_key_b64:
                    logger.error("No session key from server")
                    return False
                try:
                    self.session_key = base64.b64decode(session_key_b64)
                except Exception as e:
                    logger.error(f"Session key decode failed: {e}")
                    return False
                try:
                    self.cipher = DeimosCipher(dll_path=self.dll_path) if self.dll_path else DeimosCipher()
                    if hasattr(self.cipher, 'init_cipher'):
                        self.cipher.init_cipher(self.session_key)
                    elif hasattr(self.cipher, 'set_key'):
                        self.cipher.set_key(self.session_key)
                    else:
                        logger.warning("No cipher init method")
                except Exception as e:
                    logger.error(f"Cipher init failed: {e}")
                    return False
                logger.info(f"Auth OK. Client ID: {self.client_id}")
                return True
            else:
                logger.error(f"Auth failed: {response.get('message')}")
                return False

        except json.JSONDecodeError as e:
            logger.error(f"Bad JSON in handshake: {e}")
            return False
        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            return False

    def send_encrypted_data(self, data: bytes) -> bool:
        try:
            if not self.authenticated or not self.socket or not self.cipher:
                logger.error("Not authenticated or cipher missing")
                return False
            session_key_str = base64.b64encode(self.session_key).decode('utf-8')
            encrypted_data = self.cipher.encrypt_bytes(data, session_key_str)
            length_bytes = len(encrypted_data).to_bytes(4, 'big')
            self.socket.send(length_bytes)
            self.socket.send(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Send encrypted failed: {e}")
            return False

    def receive_encrypted_data(self) -> Optional[bytes]:
        try:
            if not self.authenticated or not self.socket or not self.cipher:
                return None
            length_bytes = self.socket.recv(4)
            if len(length_bytes) != 4:
                return None
            data_length = int.from_bytes(length_bytes, 'big')
            if data_length > 1000000:
                logger.error(f"Data too large: {data_length}")
                return None
            encrypted_data = b''
            while len(encrypted_data) < data_length:
                remaining = data_length - len(encrypted_data)
                chunk = self.socket.recv(min(remaining, self.config["buffer_size"]))
                if not chunk:
                    break
                encrypted_data += chunk
            if len(encrypted_data) != data_length:
                logger.error(f"Incomplete data: {len(encrypted_data)}")
                return None
            session_key_str = base64.b64encode(self.session_key).decode('utf-8')
            decrypted_data = self.cipher.decrypt_bytes(encrypted_data, session_key_str)
            return decrypted_data
        except Exception as e:
            logger.error(f"Receive encrypted failed: {e}")
            return None

    def start_keepalive(self):
        def keepalive_worker():
            while self.running and self.authenticated:
                try:
                    keepalive_msg = json.dumps({
                        "type": "keepalive",
                        "client_id": self.client_id,
                        "timestamp": time.time()
                    }).encode('utf-8')
                    if not self.send_encrypted_data(keepalive_msg):
                        logger.error("Keepalive send failed")
                        break
                    time.sleep(self.config["keepalive_interval"])
                except Exception as e:
                    logger.error(f"Keepalive error: {e}")
                    break
        keepalive_thread = threading.Thread(target=keepalive_worker, daemon=True)
        keepalive_thread.start()

    def handle_server_messages(self):
        def message_handler():
            while self.running and self.authenticated:
                try:
                    data = self.receive_encrypted_data()
                    if data:
                        try:
                            message = json.loads(data.decode('utf-8'))
                            self.process_server_message(message)
                        except json.JSONDecodeError:
                            if self.tunnel_manager:
                                try:
                                    self.tunnel_manager.handle_incoming_data(data)
                                except Exception as e:
                                    logger.error(f"Tunnel manager error: {e}")
                    else:
                        logger.warning("Lost connection to server")
                        self.running = False
                        break
                except Exception as e:
                    logger.error(f"Server message error: {e}")
                    break
        handler_thread = threading.Thread(target=message_handler, daemon=True)
        handler_thread.start()

    def process_server_message(self, message: Dict[str, Any]):
        msg_type = message.get("type")
        if msg_type == "tunnel_config":
            tunnel_config = message.get("config", {})
            if self.tunnel_manager:
                self.tunnel_manager.configure_tunnel(tunnel_config)
        elif msg_type == "disconnect":
            logger.info("Server asked to disconnect")
            self.disconnect()
        elif msg_type == "keepalive_response":
            pass
        else:
            logger.warning(f"Unknown message type: {msg_type}")

    def start_tunnel_manager(self):
        self.tunnel_manager = TunnelManager(
            is_server=False,
            config=self.config
        )
        self.tunnel_manager.start()

    def connect(self, username: str, password: str) -> bool:
        try:
            if not self.connect_to_server():
                return False
            if not self.perform_handshake(username, password):
                self.disconnect()
                return False
            self.running = True
            self.start_keepalive()
            self.handle_server_messages()
            self.start_tunnel_manager()
            logger.info("VPN client connected")
            return True
        except Exception as e:
            logger.error(f"Connect failed: {e}")
            self.disconnect()
            return False

    def disconnect(self):
        self.running = False
        if self.tunnel_manager:
            self.tunnel_manager.stop()
        if self.socket:
            try:
                if self.authenticated:
                    disconnect_msg = json.dumps({"type": "disconnect", "client_id": self.client_id}).encode('utf-8')
                    self.send_encrypted_data(disconnect_msg)
                self.socket.close()
            except:
                pass
            finally:
                self.socket = None
        self.authenticated = False
        self.session_key = None
        self.client_id = None
        logger.info("VPN client disconnected")

    def get_status(self) -> Dict[str, Any]:
        return {
            "connected": self.running and self.authenticated,
            "server": f"{self.server_host}:{self.server_port}",
            "client_id": self.client_id,
            "tunnel_active": self.tunnel_manager.is_active() if self.tunnel_manager else False
        }

def main():
    client = VPNClient()
    try:
        if client.connect("testuser", "testpass"):
            print("VPN connected!")
            print("Status:", client.get_status())
            while True:
                time.sleep(1)
        else:
            print("Failed to connect")
    except KeyboardInterrupt:
        print("\nShutting down VPN client...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
