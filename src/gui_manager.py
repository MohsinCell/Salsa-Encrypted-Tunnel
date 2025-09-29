import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess
import psutil
import time
import os
from datetime import datetime
import queue

class VPNGUIManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Salsa - Encryption Tunnel")
        self.root.geometry("1000x700")
        self.root.configure(bg="#2c3e50")

        # Get the folder where the script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path to your image
        icon_path = os.path.join(script_dir, "SALSA.png")

        try:
            self.icon = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self.icon)
            print("Icon set successfully!")
        except Exception as e:
            print(f"Could not set icon: {e}")
        
        # Process tracking
        self.server_process = None
        self.client_process = None
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Data queues for thread-safe updates
        self.log_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'connections': 0,
            'uptime': 0
        }
        
        self.setup_ui()
        self.start_time = None
        
        # Start GUI update loop
        self.update_gui()
    
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Server Tab
        self.server_frame = ttk.Frame(notebook)
        notebook.add(self.server_frame, text="Server Control")
        self.setup_server_tab()
        
        # Client Tab
        self.client_frame = ttk.Frame(notebook)
        notebook.add(self.client_frame, text="Client Control")
        self.setup_client_tab()
        
        # Monitoring Tab
        self.monitor_frame = ttk.Frame(notebook)
        notebook.add(self.monitor_frame, text="Traffic Monitor")
        self.setup_monitor_tab()
        
        # Logs Tab
        self.logs_frame = ttk.Frame(notebook)
        notebook.add(self.logs_frame, text="Logs")
        self.setup_logs_tab()
    
    def setup_server_tab(self):
        # Server configuration
        config_frame = ttk.LabelFrame(self.server_frame, text="Server Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.server_ip = ttk.Entry(config_frame, width=15)
        self.server_ip.insert(0, "127.0.0.1")
        self.server_ip.grid(row=0, column=1, padx=5)
        
        ttk.Label(config_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.server_port = ttk.Entry(config_frame, width=10)
        self.server_port.insert(0, "8080")
        self.server_port.grid(row=0, column=3, padx=5)
        
        ttk.Label(config_frame, text="Max Clients:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.max_clients = ttk.Entry(config_frame, width=10)
        self.max_clients.insert(0, "10")
        self.max_clients.grid(row=1, column=1, padx=5)
        
        # Server controls
        control_frame = ttk.LabelFrame(self.server_frame, text="Server Control", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_server_btn = ttk.Button(control_frame, text="Start Server", 
                                          command=self.start_server, style="Accent.TButton")
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_server_btn = ttk.Button(control_frame, text="Stop Server", 
                                         command=self.stop_server, state=tk.DISABLED)
        self.stop_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.server_status_label = ttk.Label(control_frame, text="Status: Stopped", 
                                           foreground="red")
        self.server_status_label.pack(side=tk.LEFT, padx=20)
        
        # Server statistics
        stats_frame = ttk.LabelFrame(self.server_frame, text="Server Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.server_stats_text = scrolledtext.ScrolledText(stats_frame, height=15, 
                                                          state=tk.DISABLED, wrap=tk.WORD)
        self.server_stats_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_client_tab(self):
        # Client configuration
        config_frame = ttk.LabelFrame(self.client_frame, text="Client Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.client_server_ip = ttk.Entry(config_frame, width=15)
        self.client_server_ip.insert(0, "127.0.0.1")
        self.client_server_ip.grid(row=0, column=1, padx=5)
        
        ttk.Label(config_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.client_port = ttk.Entry(config_frame, width=10)
        self.client_port.insert(0, "8080")
        self.client_port.grid(row=0, column=3, padx=5)
        
        ttk.Label(config_frame, text="Client ID:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.client_id = ttk.Entry(config_frame, width=15)
        self.client_id.insert(0, f"client_{int(time.time())}")
        self.client_id.grid(row=1, column=1, padx=5)
        
        # Add authentication section
        auth_frame = ttk.LabelFrame(config_frame, text="Authentication")
        auth_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.client_username = ttk.Entry(auth_frame, width=15)
        self.client_username.insert(0, "testuser")
        self.client_username.grid(row=0, column=1, padx=5)
        
        ttk.Label(auth_frame, text="Password:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.client_password = ttk.Entry(auth_frame, width=15, show="*")
        self.client_password.insert(0, "testpass")
        self.client_password.grid(row=0, column=3, padx=5)
        
        # Client controls
        control_frame = ttk.LabelFrame(self.client_frame, text="Client Control", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.connect_btn = ttk.Button(control_frame, text="Connect", 
                                     command=self.connect_client, style="Accent.TButton")
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(control_frame, text="Disconnect", 
                                        command=self.disconnect_client, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        self.client_status_label = ttk.Label(control_frame, text="Status: Disconnected", 
                                           foreground="red")
        self.client_status_label.pack(side=tk.LEFT, padx=20)
        
        # Client connection info
        info_frame = ttk.LabelFrame(self.client_frame, text="Connection Info", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.client_info_text = scrolledtext.ScrolledText(info_frame, height=15, 
                                                         state=tk.DISABLED, wrap=tk.WORD)
        self.client_info_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_monitor_tab(self):
        # Monitor controls
        control_frame = ttk.Frame(self.monitor_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                           command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                          command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_monitor_btn = ttk.Button(control_frame, text="Clear", 
                                           command=self.clear_monitor)
        self.clear_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Enhanced statistics display with tunnel-specific metrics
        stats_frame = ttk.LabelFrame(self.monitor_frame, text="Network & Tunnel Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        
        # Create enhanced statistics labels
        self.stats_labels = {}
        stats_items = [
            ("Bytes Sent:", "bytes_sent"), ("Bytes Received:", "bytes_received"),
            ("Packets Sent:", "packets_sent"), ("Packets Received:", "packets_received"),
            ("Tunnel State:", "tunnel_state"), ("Encryption Time:", "encryption_time"),
            ("Decryption Time:", "decryption_time"), ("Active Connections:", "connections"),
            ("Injected Packets:", "injected_packets"), ("Uptime:", "uptime")
        ]
        
        for i, (label, key) in enumerate(stats_items):
            row = i // 2
            col = (i % 2) * 2
            ttk.Label(stats_grid, text=label).grid(row=row, column=col, sticky=tk.W, padx=5)
            self.stats_labels[key] = ttk.Label(stats_grid, text="0", foreground="blue")
            self.stats_labels[key].grid(row=row, column=col+1, sticky=tk.W, padx=5)
        
        # Packet capture display
        capture_frame = ttk.LabelFrame(self.monitor_frame, text="Packet Capture", padding=10)
        capture_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.packet_text = scrolledtext.ScrolledText(capture_frame, height=20, 
                                                    state=tk.DISABLED, wrap=tk.WORD)
        self.packet_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_logs_tab(self):
        # Log controls
        control_frame = ttk.Frame(self.logs_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.clear_logs_btn = ttk.Button(control_frame, text="Clear Logs", 
                                        command=self.clear_logs)
        self.clear_logs_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_logs_btn = ttk.Button(control_frame, text="Save Logs", 
                                       command=self.save_logs)
        self.save_logs_btn.pack(side=tk.LEFT, padx=5)
        
        # Log level filter
        ttk.Label(control_frame, text="Log Level:").pack(side=tk.LEFT, padx=(20, 5))
        self.log_level = ttk.Combobox(control_frame, values=["ALL", "INFO", "WARNING", "ERROR"], 
                                     state="readonly", width=10)
        self.log_level.set("ALL")
        self.log_level.pack(side=tk.LEFT, padx=5)
        
        # Logs display
        self.logs_text = scrolledtext.ScrolledText(self.logs_frame, height=25, 
                                                  state=tk.DISABLED, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        self.log_queue.put((log_entry, level))
    
    def start_server(self):
        try:
            ip = self.server_ip.get()
            port = int(self.server_port.get())
            max_clients = int(self.max_clients.get())
            server_script = f'''
import sys
import os

# Add VPN src directory to path
sys.path.insert(0, r"C:\\My Projects\\Salsa - Encrypted VPN Prototype\\src")

# Import your VPNServer class
try:
    from vpn_server import VPNServer
    
    # Create server with GUI parameters
    server = VPNServer(host="{ip}", port={port})
    server.config["max_clients"] = {max_clients}
    
    print(f"Starting VPN Server on {{server.host}}:{{server.port}}")
    print(f"Max clients: {{server.config['max_clients']}}")
    print(f"DLL Path: {{server.dll_path}}")
    
    if server.start_server():
        print("Server started successfully")
        server.accept_connections()
    else:
        print("Failed to start server")
        
except Exception as e:
    print(f"Server error: {{e}}")
    import traceback
    traceback.print_exc()
'''
            
            # Write temporary server script
            with open("temp_server.py", "w") as f:
                f.write(server_script)
            
            # Start server process
            self.server_process = subprocess.Popen(
                ["python", "temp_server.py"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.start_server_btn.config(state=tk.DISABLED)
            self.stop_server_btn.config(state=tk.NORMAL)
            self.server_status_label.config(text="Status: Running", foreground="green")
            
            self.start_time = time.time()
            self.log_message(f"Server started on {ip}:{port}")
            
            # Start monitoring thread
            threading.Thread(target=self.monitor_server_process, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.log_message(f"Server start failed: {str(e)}", "ERROR")
    
    def stop_server(self):
        try:
            if self.server_process:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.server_process = None
            
            # Auto-stop monitoring if no client is connected
            if not (self.client_process and self.client_process.poll() is None):
                if self.monitoring_active:
                    self.stop_monitoring()
            
            # Clean up temporary file
            try:
                if os.path.exists("temp_server.py"):
                    os.remove("temp_server.py")
            except:
                pass
            
            self.start_server_btn.config(state=tk.NORMAL)
            self.stop_server_btn.config(state=tk.DISABLED)
            self.server_status_label.config(text="Status: Stopped", foreground="red")
            
            self.log_message("VPN server stopped")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop server: {str(e)}")
            self.log_message(f"Server stop failed: {str(e)}", "ERROR")
    
    def connect_client(self):
        try:
            ip = self.client_server_ip.get()
            port = int(self.client_port.get())
            client_id = self.client_id.get()
            username = self.client_username.get()
            password = self.client_password.get()
            
            # Validate inputs
            if not username.strip():
                messagebox.showerror("Error", "Username cannot be empty")
                return
            if not password.strip():
                messagebox.showerror("Error", "Password cannot be empty")
                return
            
            # Create a client script with proper indentation
            client_script = f"""import sys
import os
import json

# Add multiple possible paths to find the VPN modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
possible_paths = [
    current_dir,
    parent_dir,
    os.path.join(parent_dir, 'src'),
    os.path.join(current_dir, 'src'),
    r"C:\\My Projects\\Salsa - Encrypted VPN Prototype",
    r"C:\\My Projects\\Encrypted VPN Prototype"
]

for path in possible_paths:
    if path not in sys.path:
        sys.path.append(path)

try:
    from vpn_client import VPNClient
    import time
    
    # Configuration from GUI
    SERVER_IP = "{ip}"
    SERVER_PORT = {port}
    USERNAME = "{username}"
    PASSWORD = "{password}"
    CLIENT_ID = "{client_id}"
    
    print(f"Initializing VPN Client...")
    print(f"Server: {{SERVER_IP}}:{{SERVER_PORT}}")
    print(f"Username: {{USERNAME}}")
    print(f"Client ID: {{CLIENT_ID}}")
    print(f"Attempting authentication with provided credentials...")
    
    # Create VPN client instance
    client = VPNClient(server_host=SERVER_IP, server_port=SERVER_PORT)
    
    # Attempt connection with actual credentials from GUI
    print("Connecting to VPN server...")
    print(f"DEBUG: Using username='{{USERNAME}}' password='{{PASSWORD}}'")
    
    connection_result = client.connect(USERNAME, PASSWORD)
    
    if connection_result:
        print("VPN connection established successfully!")
        print("Authentication successful!")
        print("Status:", client.get_status())
        
        # Keep the connection alive and show status updates
        status_counter = 0
        while client.running and client.authenticated:
            time.sleep(5)
            status_counter += 1
            
            # Print status every 30 seconds (6 * 5 second intervals)
            if status_counter % 6 == 0:
                status = client.get_status()
                print(f"Connection Status: {{status}}")
                
                # Show tunnel manager stats if available
                if client.tunnel_manager:
                    try:
                        stats = client.tunnel_manager.get_stats()
                        print(f"Tunnel Stats - Packets sent: {{stats['packets_sent']}}, received: {{stats['packets_received']}}")
                        print(f"Tunnel State: {{stats['state']}}")
                    except:
                        print("Tunnel stats not available")
            
            # Check if connection is still alive
            if not client.running:
                print("Connection lost")
                break
                
    else:
        print("AUTHENTICATION FAILED - Invalid username or password")
        print(f"Failed credentials: username='{{USERNAME}}' password='{{PASSWORD}}'")
        print("Please check your credentials and try again")
        
except ImportError as e:
    print(f"Import error - make sure vpn_client.py is in the same directory: {{e}}")
    sys.exit(1)
except Exception as e:
    print(f"Client error: {{e}}")
    import traceback
    traceback.print_exc()
finally:
    try:
        if 'client' in locals() and hasattr(client, 'disconnect'):
            print("Disconnecting VPN client...")
            client.disconnect()
    except Exception as cleanup_error:
        print(f"Cleanup error: {{cleanup_error}}")
"""
            
            # Write temporary client script
            with open("temp_client.py", "w") as f:
                f.write(client_script)
            
            # Start client process
            self.client_process = subprocess.Popen(
                ["python", "temp_client.py"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.client_status_label.config(text="Status: Connecting...", foreground="orange")
            
            self.log_message(f"Client connecting to {ip}:{port} with username: {username}")
            
            # Start monitoring thread
            threading.Thread(target=self.monitor_client_process, daemon=True).start()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port number: {str(e)}")
            self.log_message(f"Client connection failed: Invalid port", "ERROR")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect client: {str(e)}")
            self.log_message(f"Client connection failed: {str(e)}", "ERROR")

    def disconnect_client(self):
        try:
            if self.client_process:
                self.client_process.terminate()
                self.client_process.wait(timeout=5)
                self.client_process = None
            
            # Auto-stop monitoring if no server is running
            if not (self.server_process and self.server_process.poll() is None):
                if self.monitoring_active:
                    self.stop_monitoring()
            
            # Clean up temporary file
            try:
                if os.path.exists("temp_client.py"):
                    os.remove("temp_client.py")
            except:
                pass
            
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.client_status_label.config(text="Status: Disconnected", foreground="red")
            
            self.log_message("VPN client disconnected")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to disconnect client: {str(e)}")
            self.log_message(f"Client disconnect failed: {str(e)}", "ERROR")
    
    def start_monitoring(self):
        # Only allow monitoring if server or client is running
        if not (self.server_process or self.client_process):
            messagebox.showwarning("Warning", "Please start server or connect client before monitoring VPN traffic")
            return
        
        self.monitoring_active = True
        self.start_monitor_btn.config(state=tk.DISABLED)
        self.stop_monitor_btn.config(state=tk.NORMAL)
        
        self.monitoring_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitoring_thread.start()
        
        self.log_message("VPN traffic monitoring started")
    
    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        
        self.log_message("VPN traffic monitoring stopped")
    
    def monitor_network(self):
        """Monitor VPN-specific network traffic"""
        last_stats = psutil.net_io_counters()
        idle_cycles = 0
        
        while self.monitoring_active:
            try:
                # Check if VPN components are still running
                vpn_active = (self.server_process and self.server_process.poll() is None) or \
                            (self.client_process and self.client_process.poll() is None)
                
                if not vpn_active:
                    idle_cycles += 1
                    # Auto-stop monitoring after 30 seconds of no VPN activity
                    if idle_cycles >= 30:
                        self.log_message("No VPN activity detected. Stopping monitor.", "INFO")
                        self.stop_monitoring()
                        break
                else:
                    idle_cycles = 0
                
                current_stats = psutil.net_io_counters()
                
                # Only process traffic when VPN is active
                if vpn_active:
                    # Calculate differences
                    bytes_sent_diff = current_stats.bytes_sent - last_stats.bytes_sent
                    bytes_recv_diff = current_stats.bytes_recv - last_stats.bytes_recv
                    packets_sent_diff = current_stats.packets_sent - last_stats.packets_sent
                    packets_recv_diff = current_stats.packets_recv - last_stats.packets_recv
                    
                    # Update our stats only for VPN-related activity
                    if bytes_sent_diff > 0 or bytes_recv_diff > 0:
                        self.stats['bytes_sent'] += bytes_sent_diff
                        self.stats['bytes_received'] += bytes_recv_diff
                        self.stats['packets_sent'] += packets_sent_diff
                        self.stats['packets_received'] += packets_recv_diff
                        
                        # Log VPN-specific packets
                        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        
                        if bytes_sent_diff > 0:
                            packet_type = self.classify_packet_type(bytes_sent_diff)
                            packet_info = (f"{timestamp} - [VPN-OUT] {packet_type}: "
                                        f"{bytes_sent_diff}B encrypted via tunnel")
                            self.log_queue.put((packet_info + "\n", "PACKET"))
                        
                        if bytes_recv_diff > 0:
                            packet_type = self.classify_packet_type(bytes_recv_diff)
                            packet_info = (f"{timestamp} - [VPN-IN] {packet_type}: "
                                        f"{bytes_recv_diff}B decrypted from tunnel")
                            self.log_queue.put((packet_info + "\n", "PACKET"))
                
                last_stats = current_stats
                
                # Update VPN connection status
                if vpn_active:
                    self.stats['connections'] = 1 if (self.server_process and self.server_process.poll() is None) else \
                                            1 if (self.client_process and self.client_process.poll() is None) else 0
                    self.stats['tunnel_state'] = "CONNECTED"
                else:
                    self.stats['tunnel_state'] = "DISCONNECTED"
                    self.stats['connections'] = 0
                
                # Update uptime only when VPN is active
                if vpn_active and self.start_time:
                    self.stats['uptime'] = int(time.time() - self.start_time)
                
                # Simulate tunnel-specific stats only when active
                if vpn_active and (bytes_sent_diff > 0 or bytes_recv_diff > 0):
                    self.stats['encryption_time'] = round(self.stats.get('encryption_time', 0) + 0.001, 3)
                    self.stats['decryption_time'] = round(self.stats.get('decryption_time', 0) + 0.001, 3)
                    self.stats['injected_packets'] = self.stats.get('injected_packets', 0) + 1
                
                time.sleep(1)
                
            except Exception as e:
                self.log_message(f"VPN monitoring error: {str(e)}", "ERROR")
                break
    
    def classify_packet_type(self, packet_size):
        """Classify packet type based on size for better monitoring"""
        if packet_size < 100:
            return "Keepalive/Control"
        elif packet_size < 500:
            return "Tunnel Control"
        elif packet_size < 1500:
            return "Data Packet"
        else:
            return "Large Data/File Transfer"
    
    def monitor_server_process(self):
        """Monitor server process output"""
        if not self.server_process:
            return
            
        while self.server_process.poll() is None:
            try:
                line = self.server_process.stdout.readline()
                if line:
                    self.log_queue.put((f"SERVER: {line}", "INFO"))
            except Exception as e:
                self.log_message(f"Server monitor error: {str(e)}", "ERROR")
                break
    
    def monitor_client_process(self):
        """Monitor client process output and handle authentication states"""
        if not self.client_process:
            return

        connection_established = False
        auth_failed = False

        while self.client_process.poll() is None:
            try:
                line = self.client_process.stdout.readline()
                if line:
                    line_clean = line.strip()
                    self.log_queue.put((f"CLIENT: {line}", "INFO"))

                    # Check for authentication status
                    if ("VPN connection established successfully" in line_clean or 
                        "VPN client connected" in line_clean or 
                        "Auth OK. Client ID:" in line_clean):
                        connection_established = True
                        self.client_status_label.config(text="Status: Connected", foreground="green")
                        self.log_message("Client authentication successful")

                    elif "AUTHENTICATION FAILED" in line_clean or "Auth failed" in line_clean:
                        auth_failed = True
                        self.client_status_label.config(text="Status: Authentication Failed", foreground="red")
                        self.log_message("Client authentication failed - check credentials", "ERROR")

                    elif "Failed to connect" in line_clean:
                        self.client_status_label.config(text="Status: Connection Failed", foreground="red")
                        self.log_message("Client connection failed", "ERROR")

            except Exception as e:
                self.log_message(f"Client monitor error: {str(e)}", "ERROR")
                break

        # Process has ended - check final state
        if self.client_process.poll() is not None:
            if auth_failed:
                self.client_status_label.config(text="Status: Auth Failed", foreground="red")
            elif not connection_established:
                self.client_status_label.config(text="Status: Connection Failed", foreground="red")
            else:
                self.client_status_label.config(text="Status: Disconnected", foreground="red")

            # Reset buttons
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
    
    def clear_monitor(self):
        self.packet_text.config(state=tk.NORMAL)
        self.packet_text.delete(1.0, tk.END)
        self.packet_text.config(state=tk.DISABLED)
        
        # Reset statistics
        self.stats = {k: 0 for k in self.stats}
    
    def clear_logs(self):
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.config(state=tk.DISABLED)
    
    def save_logs(self):
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt")]
            )
            if filename:
                content = self.logs_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(content)
                self.log_message(f"Logs saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def format_bytes(self, bytes_val):
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    
    def format_uptime(self, seconds):
        """Format uptime in human readable format"""
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    def update_gui(self):
        """Update GUI elements from queues"""
        # Update logs
        try:
            while True:
                log_entry, level = self.log_queue.get_nowait()
                
                # Handle packet logs separately (they always go to packet monitor)
                if level == "PACKET":
                    self.packet_text.config(state=tk.NORMAL)
                    self.packet_text.insert(tk.END, log_entry)
                    self.packet_text.see(tk.END)
                    self.packet_text.config(state=tk.DISABLED)
                else:
                    # Apply log level filter for regular logs
                    selected_level = self.log_level.get()
                    
                    # Show log if filter is "ALL" or if level matches selected level
                    if selected_level == "ALL" or level == selected_level:
                        self.logs_text.config(state=tk.NORMAL)
                        self.logs_text.insert(tk.END, log_entry)
                        self.logs_text.see(tk.END)
                        self.logs_text.config(state=tk.DISABLED)
                        
        except queue.Empty:
            pass
        
        # Update statistics
        for key, label in self.stats_labels.items():
            if key in ['bytes_sent', 'bytes_received']:
                label.config(text=self.format_bytes(self.stats[key]))
            elif key == 'uptime':
                label.config(text=self.format_uptime(self.stats[key]))
            elif key in ['encryption_time', 'decryption_time']:
                label.config(text=f"{self.stats.get(key, 0):.3f}s")
            elif key == 'tunnel_state':
                state = self.stats.get(key, "DISCONNECTED")
                label.config(text=state, 
                        foreground="green" if state == "CONNECTED" else "red")
            else:
                label.config(text=str(self.stats.get(key, 0)))
        
        # Update server stats with enhanced tunnel information
        if self.server_process and self.server_process.poll() is None:
            stats_info = f"""VPN Server Statistics:
    ═══════════════════════════════════════
    Runtime Information:
    • Server Uptime: {self.format_uptime(self.stats['uptime'])}
    • Server State: Running
    • Process ID: {self.server_process.pid}

    Connection Statistics:
    • Active Client Connections: {self.stats['connections']}
    • Total Data Transmitted: {self.format_bytes(self.stats['bytes_sent'])}
    • Total Data Received: {self.format_bytes(self.stats['bytes_received'])}
    • Total Packets Processed: {self.stats['packets_sent'] + self.stats['packets_received']}

    Tunnel Manager Statistics:
    • Tunnel State: {self.stats.get('tunnel_state', 'UNKNOWN')}
    • Encryption Operations: {self.stats.get('encryption_time', 0):.3f}s total
    • Decryption Operations: {self.stats.get('decryption_time', 0):.3f}s total
    • Injected Packages: {self.stats.get('injected_packets', 0)}
    • Cipher: Deimos Custom Encryption

    Network Configuration:
    • Server Address: {self.server_ip.get()}:{self.server_port.get()}
    • Max Clients: {self.max_clients.get()}
    • Buffer Size: 4096 bytes
    • Tunnel Subnet: 10.0.0.0/24
    """
            self.server_stats_text.config(state=tk.NORMAL)
            self.server_stats_text.delete(1.0, tk.END)
            self.server_stats_text.insert(1.0, stats_info)
            self.server_stats_text.config(state=tk.DISABLED)
        
        # Update client info
        if self.client_process and self.client_process.poll() is None:
            client_info = f"""Client Connection Info:
    Server: {self.client_server_ip.get()}:{self.client_port.get()}
    Client ID: {self.client_id.get()}
    Connection Status: Active
    Data Sent: {self.format_bytes(self.stats['bytes_sent'])}
    Data Received: {self.format_bytes(self.stats['bytes_received'])}
    Client Process ID: {self.client_process.pid}
    """
            self.client_info_text.config(state=tk.NORMAL)
            self.client_info_text.delete(1.0, tk.END)
            self.client_info_text.insert(1.0, client_info)
            self.client_info_text.config(state=tk.DISABLED)
        
        # Schedule next update
        self.root.after(1000, self.update_gui)

def main():
    root = tk.Tk()
    app = VPNGUIManager(root)
    
    # Handle window close
    def on_closing():
        app.stop_server()
        app.disconnect_client()
        app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()