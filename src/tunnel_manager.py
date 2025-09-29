import socket
import struct
import threading
import time
import logging
import base64
from typing import Dict, Optional, Callable, Tuple, List, Any
from dataclasses import dataclass
from enum import Enum
import queue
import sys
import os

# Import cipher wrapper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from deimos_wrapper import DeimosCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TunnelState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

@dataclass
class TunnelConfig:
    mtu: int = 1500
    cipher_password: str = "password"
    keepalive_interval: int = 30
    timeout: int = 10
    buffer_size: int = 4096
    subnet: str = "10.0.0.0/24"
    dns_servers: List[str] = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = ['8.8.8.8', '8.8.4.4']
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'TunnelConfig':
        instance = cls()
        for key, value in config_dict.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
            else:
                logger.warning(f"Unknown config parameter: {key}")
        return instance
    
    def update(self, config_dict: Dict[str, Any]):
        for key, value in config_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                logger.warning(f"Unknown config parameter: {key}")

@dataclass
class PacketHeader:
    packet_id: int
    packet_type: int
    payload_size: int
    timestamp: float
    
    def pack(self) -> bytes:
        return struct.pack('!IIIf', self.packet_id, self.packet_type, 
                          self.payload_size, self.timestamp)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'PacketHeader':
        packet_id, packet_type, payload_size, timestamp = struct.unpack('!IIIf', data)
        return cls(packet_id, packet_type, payload_size, timestamp)

class TunnelManager:
    HEADER_SIZE = 16
    
    def __init__(self, config=None, is_server: bool = False, session_key: bytes = None, 
                 control_socket: socket.socket = None, dll_path: str = None):
        if isinstance(config, dict):
            self.config = TunnelConfig.from_dict(config)
        elif isinstance(config, TunnelConfig):
            self.config = config
        else:
            self.config = TunnelConfig()
        
        self.is_server = is_server
        self.state = TunnelState.DISCONNECTED
        self.control_socket = control_socket
        self.session_key = session_key
        
        if session_key is not None:
            if isinstance(session_key, bytes):
                self.cipher_password = session_key.hex()
            else:
                self.cipher_password = str(session_key)
        else:
            self.cipher_password = self.config.cipher_password
        
        try:
            if not dll_path:
                dll_path = self._find_dll_path()
            self.cipher = DeimosCipher(dll_path=dll_path) if dll_path else DeimosCipher()
            if session_key:
                if hasattr(self.cipher, 'init_cipher'):
                    self.cipher.init_cipher(session_key if isinstance(session_key, bytes) else session_key.encode())
                elif hasattr(self.cipher, 'set_key'):
                    self.cipher.set_key(session_key if isinstance(session_key, bytes) else session_key.encode())
        except Exception as e:
            logger.error(f"Failed to initialize cipher: {e}")
            raise
        
        self.packet_id_counter = 0
        self.injection_queue = queue.Queue()
        self.outbound_queue = queue.Queue()
        self.running = False
        self.threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.start_time = None
        self.stats = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'encryption_time': 0.0,
            'decryption_time': 0.0,
            'injected_packets': 0,
            'control_packets_sent': 0,
            'control_packets_received': 0,
            'encryption_errors': 0,
            'decryption_errors': 0
        }
        self.on_state_change: Optional[Callable[[TunnelState], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None
        self.on_data_ready: Optional[Callable[[bytes], None]] = None
    
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
                return path
        logger.warning("DLL not found in standard locations")
        return None
    
    def encrypt_packet(self, data: bytes) -> bytes:
        start_time = time.time()
        try:
            if hasattr(self.cipher, 'encrypt_bytes'):
                encrypted = self.cipher.encrypt_bytes(data, self.cipher_password)
            else:
                if isinstance(data, bytes):
                    data_str = base64.b64encode(data).decode('utf-8')
                    encrypted_str = self.cipher.encrypt(data_str, self.cipher_password)
                    encrypted = base64.b64decode(encrypted_str.encode('utf-8'))
                else:
                    encrypted = self.cipher.encrypt(data, self.cipher_password)
            self.stats['encryption_time'] += time.time() - start_time
            return encrypted
        except Exception as e:
            self.stats['encryption_errors'] += 1
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_packet(self, data: bytes) -> bytes:
        start_time = time.time()
        try:
            if hasattr(self.cipher, 'decrypt_bytes'):
                decrypted = self.cipher.decrypt_bytes(data, self.cipher_password)
            else:
                if isinstance(data, bytes):
                    data_str = base64.b64encode(data).decode('utf-8')
                    decrypted_str = self.cipher.decrypt(data_str, self.cipher_password)
                    decrypted = base64.b64decode(decrypted_str.encode('utf-8'))
                else:
                    decrypted = self.cipher.decrypt(data, self.cipher_password)
            self.stats['decryption_time'] += time.time() - start_time
            return decrypted
        except Exception as e:
            self.stats['decryption_errors'] += 1
            logger.error(f"Decryption failed: {e}")
            raise
    
    def create_packet(self, payload: bytes, packet_type: int = 0) -> bytes:
        with self._lock:
            self.packet_id_counter += 1
            packet_id = self.packet_id_counter
        try:
            encrypted_payload = self.encrypt_packet(payload)
            header = PacketHeader(
                packet_id=packet_id,
                packet_type=packet_type,
                payload_size=len(encrypted_payload),
                timestamp=time.time()
            )
            packet = header.pack() + encrypted_payload
            return packet
        except Exception as e:
            logger.error(f"Failed to create packet: {e}")
            raise
    
    def parse_packet(self, data: bytes) -> Tuple[PacketHeader, bytes]:
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Packet too small")
        try:
            header_bytes = data[:self.HEADER_SIZE]
            header = PacketHeader.unpack(header_bytes)
            encrypted_payload = data[self.HEADER_SIZE:]
            if len(encrypted_payload) != header.payload_size:
                raise ValueError("Payload size mismatch")
            decrypted_payload = self.decrypt_packet(encrypted_payload)
            return header, decrypted_payload
        except Exception as e:
            logger.error(f"Failed to parse packet: {e}")
            raise
    
    def send_packet(self, data: bytes, packet_type: int = 0) -> bool:
        try:
            packet = self.create_packet(data, packet_type)
            self.outbound_queue.put(packet, block=False)
            if self.on_data_ready:
                self.on_data_ready(packet)
            self.stats['bytes_sent'] += len(packet)
            self.stats['packets_sent'] += 1
            self.stats['control_packets_sent'] += 1
            return True
        except queue.Full:
            logger.warning("Outbound queue is full, dropping packet")
            return False
        except Exception as e:
            logger.error(f"Failed to queue packet: {e}")
            return False
    
    def get_outbound_data(self) -> Optional[bytes]:
        try:
            return self.outbound_queue.get(block=False)
        except queue.Empty:
            return None
    
    def handle_incoming_data(self, data: bytes):
        try:
            header, payload = self.parse_packet(data)
            self.stats['bytes_received'] += len(data)
            self.stats['packets_received'] += 1
            self.stats['control_packets_received'] += 1
            if header.packet_type == 0:
                logger.debug(f"Received data packet: {len(payload)} bytes")
            elif header.packet_type == 2:
                logger.debug("Received keepalive packet")
            elif header.packet_type == 3:
                logger.debug(f"Received injected packet: {len(payload)} bytes")
        except Exception as e:
            logger.error(f"Error handling incoming control data: {e}")
    
    def inject_packet(self, data: bytes):
        try:
            self.injection_queue.put(data, block=False)
            self.stats['injected_packets'] += 1
            logger.debug(f"Injected packet of {len(data)} bytes")
        except queue.Full:
            logger.warning("Injection queue is full, dropping packet")
    
    def process_injected_packets(self):
        try:
            while not self.injection_queue.empty():
                data = self.injection_queue.get(block=False)
                self.send_packet(data, packet_type=3)
        except queue.Empty:
            pass
        except Exception as e:
            logger.error(f"Error processing injected packets: {e}")
    
    def tunnel_worker(self):
        logger.info("Tunnel worker started")
        while self.running:
            try:
                self.process_injected_packets()
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in tunnel worker: {e}")
                if self.on_error:
                    self.on_error(e)
    
    def keepalive_worker(self):
        logger.info("Keepalive worker started")
        while self.running:
            try:
                keepalive_data = b"keepalive"
                self.send_packet(keepalive_data, packet_type=2)
                time.sleep(self.config.keepalive_interval)
            except Exception as e:
                logger.error(f"Error in keepalive worker: {e}")
    
    def set_state(self, new_state: TunnelState):
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            logger.info(f"Tunnel state changed: {old_state.value} -> {new_state.value}")
            if self.on_state_change:
                self.on_state_change(new_state)
    
    def start_tunnel(self) -> bool:
        try:
            self.set_state(TunnelState.CONNECTING)
            self.start_time = time.time()
            self.running = True
            tunnel_thread = threading.Thread(target=self.tunnel_worker, daemon=True)
            keepalive_thread = threading.Thread(target=self.keepalive_worker, daemon=True)
            tunnel_thread.start()
            keepalive_thread.start()
            self.threads = [tunnel_thread, keepalive_thread]
            self.set_state(TunnelState.CONNECTED)
            logger.info("VPN tunnel started successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to start tunnel: {e}")
            self.set_state(TunnelState.ERROR)
            if self.on_error:
                self.on_error(e)
            return False
    
    def stop_tunnel(self):
        try:
            self.set_state(TunnelState.DISCONNECTING)
            self.running = False
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            self._clear_queues()
            self.set_state(TunnelState.DISCONNECTED)
            logger.info("VPN tunnel stopped")
        except Exception as e:
            logger.error(f"Error stopping tunnel: {e}")
            self.set_state(TunnelState.ERROR)
    
    def _clear_queues(self):
        queues = [self.injection_queue, self.outbound_queue]
        for q in queues:
            while not q.empty():
                try:
                    q.get(block=False)
                except queue.Empty:
                    break
    
    def start(self) -> bool:
        return self.start_tunnel()
    
    def stop(self):
        self.stop_tunnel()
    
    def is_active(self) -> bool:
        return self.is_connected()
    
    def configure_tunnel(self, config: dict):
        self.config.update(config)
        logger.info(f"Tunnel configuration updated: {config}")
    
    def get_stats(self) -> Dict:
        stats = self.stats.copy()
        stats['state'] = self.state.value
        stats['uptime'] = (time.time() - self.start_time) if self.start_time else 0
        stats['injection_queue_size'] = self.injection_queue.qsize()
        stats['outbound_queue_size'] = self.outbound_queue.qsize()
        return stats
    
    def is_connected(self) -> bool:
        return self.state == TunnelState.CONNECTED

def create_server_tunnel_manager(session_key: bytes, client_id: str, 
                                 control_socket: socket.socket = None,
                                 config: dict = None) -> TunnelManager:
    default_config = {
        "mtu": 1500,
        "keepalive_interval": 30,
        "timeout": 10,
        "buffer_size": 4096,
        "subnet": "10.0.0.0/24",
        "dns_servers": ["8.8.8.8", "8.8.4.4"]
    }
    if config:
        default_config.update(config)
    manager = TunnelManager(
        config=default_config,
        is_server=True,
        session_key=session_key,
        control_socket=control_socket
    )
    logger.info(f"Created server tunnel manager for client {client_id}")
    return manager

def create_client_tunnel_manager(session_key: bytes, server_host: str,
                                 control_socket: socket.socket = None,
                                 config: dict = None) -> TunnelManager:
    default_config = {
        "mtu": 1500,
        "keepalive_interval": 30,
        "timeout": 10,
        "buffer_size": 4096,
        "subnet": "10.0.0.0/24",
        "dns_servers": ["8.8.8.8", "8.8.4.4"]
    }
    if config:
        default_config.update(config)
    manager = TunnelManager(
        config=default_config,
        is_server=False,
        session_key=session_key,
        control_socket=control_socket
    )
    logger.info(f"Created client tunnel manager for server {server_host}")
    return manager

if __name__ == "__main__":
    print("Testing simplified tunnel manager...")
    import secrets
    session_key = secrets.token_bytes(32)
    def on_state_change(state):
        print(f"State changed to: {state.value}")
    def on_data_ready(data):
        print(f"Data ready for control channel: {len(data)} bytes")
    config = {
        "subnet": "10.0.0.0/24",
        "dns_servers": ["8.8.8.8", "8.8.4.4"],
        "mtu": 1500,
        "buffer_size": 4096,
        "timeout": 30
    }
    manager = create_server_tunnel_manager(
        session_key=session_key,
        client_id="test-client-123",
        config=config
    )
    manager.on_state_change = on_state_change
    manager.on_data_ready = on_data_ready
    try:
        if manager.start():
            print("Tunnel started successfully")
            print(f"Is active: {manager.is_active()}")
            test_data = b"Hello, simplified VPN!"
            manager.inject_packet(test_data)
            time.sleep(2)
            print(f"Stats: {manager.get_stats()}")
            manager.stop()
            print("Tunnel stopped")
        else:
            print("Failed to start tunnel")
    except KeyboardInterrupt:
        print("Stopping...")
        manager.stop()
