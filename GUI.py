import pydivert
import threading
import time
import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw
import sys
import re
import subprocess
import platform

# --- Logic Backend ---
class BandwidthManager:
    def __init__(self):
        self.dl_limit = 0  
        self.ul_limit = 0
        self.is_running = True  # Always run to collect stats
        self.limiting_active = False  # Only True when limits > 0
        self.dl_bytes_counted = 0
        self.ul_bytes_counted = 0
        
        # Token bucket for rate limiting
        self.dl_tokens = 1000.0  # Large initial burst
        self.ul_tokens = 1000.0
        self.last_dl_time = time.time()
        self.last_ul_time = time.time()
        self.max_burst_kb = 1000
        
        self.stats_lock = threading.Lock()
        self.packet_thread = None
        # Detected VPN-related local IP addresses to exclude from interception
        self.vpn_ips = set()
        # Try to detect VPN adapter IPs up-front
        try:
            self.vpn_ips = self.detect_vpn_ips()
        except Exception:
            self.vpn_ips = set()
        # Whether packet interception is currently enabled
        self.interception_enabled = True
        # If True, automatically disable interception when a VPN adapter is detected
        self.auto_disable_on_vpn = True
        # Apply auto-disable immediately if we detected VPN IPs
        if self.auto_disable_on_vpn and self.vpn_ips:
            self.interception_enabled = False

    def update_limiting_state(self):
        """Update whether rate limiting should be applied"""
        if self.dl_limit > 0 or self.ul_limit > 0:
            self.limiting_active = True
            # Refill token buckets to prevent initial stall
            self.dl_tokens = self.max_burst_kb
            self.ul_tokens = self.max_burst_kb
            self.last_dl_time = time.time()
            self.last_ul_time = time.time()
        else:
            self.limiting_active = False

    def detect_vpn_ips(self):
        """Detect local IPv4 addresses for adapters that look like VPN adapters.

        Returns a set of IP address strings. This uses `ipconfig` on Windows and
        looks for common VPN adapter names (e.g., "TAP", "TUN", "WAN Miniport", "Surfshark").
        """
        ips = set()
        if platform.system().lower() != 'windows':
            return ips

        try:
            output = subprocess.check_output(['ipconfig'], text=True, encoding='utf-8', errors='ignore')
        except Exception:
            return ips

        # Split into adapter sections
        sections = re.split(r"\r?\n\r?\n", output)
        for sec in sections:
            header = sec.strip().splitlines()[0] if sec.strip() else ''
            # Heuristic: skip adapters that look like physical ethernet/wifi
            if any(x in header.lower() for x in ('ethernet adapter', 'wireless lan adapter', 'wi-fi', 'local area connection')):
                continue

            # Look for keywords that indicate a VPN or virtual adapter
            if any(k in header.lower() for k in ('tap', 'tun', 'vpn', 'virtual', 'surfshark', 'wan miniport')):
                # Find IPv4 Address lines
                for m in re.finditer(r'IPv4 Address[^:\r\n]*:\s*([0-9]+(?:\.[0-9]+){3})', sec):
                    ips.add(m.group(1))
                for m in re.finditer(r'IP Address[^:\r\n]*:\s*([0-9]+(?:\.[0-9]+){3})', sec):
                    ips.add(m.group(1))

        return ips

    def _packet_loop(self):
        # Run continuously, but only open WinDivert when interception is enabled
        while self.is_running:
            # Refresh VPN IP list periodically and respect auto-disable setting
            try:
                current_vpn_ips = self.detect_vpn_ips()
                self.vpn_ips.update(current_vpn_ips)
            except Exception:
                current_vpn_ips = set()

            if self.auto_disable_on_vpn and self.vpn_ips:
                self.interception_enabled = False
            elif not self.vpn_ips and self.auto_disable_on_vpn:
                self.interception_enabled = True

            if not getattr(self, 'interception_enabled', True):
                # Sleep briefly and re-evaluate
                time.sleep(0.5)
                continue

            # Build a WinDivert filter that excludes loopback and any detected VPN adapter IPs
            filter_str = "(tcp or udp) and ip.SrcAddr != 127.0.0.1 and ip.DstAddr != 127.0.0.1"
            for vip in list(self.vpn_ips):
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", vip):
                    filter_str += f" and ip.SrcAddr != {vip} and ip.DstAddr != {vip}"

            w = None
            try:
                # Lower priority to avoid conflicts with VPN drivers
                w = pydivert.WinDivert(filter_str, priority=1000)
                w.open()

                for packet in w:
                    if not self.is_running or not getattr(self, 'interception_enabled', True):
                        break

                    is_out = packet.is_outbound
                    size_kb = len(packet.raw) / 1024

                    # Apply rate limiting BEFORE sending packet
                    if self.limiting_active:
                        limit = self.ul_limit if is_out else self.dl_limit

                        if limit > 0:
                            if is_out:
                                now = time.time()
                                elapsed = now - self.last_ul_time

                                # Add tokens based on elapsed time
                                self.ul_tokens += elapsed * limit
                                self.ul_tokens = min(self.ul_tokens, self.max_burst_kb)

                                # Check if we need to wait
                                if self.ul_tokens < size_kb:
                                    needed = size_kb - self.ul_tokens
                                    sleep_time = needed / limit
                                    time.sleep(sleep_time)
                                    # Update time after sleep
                                    now = time.time()
                                    elapsed = now - self.last_ul_time
                                    self.ul_tokens += elapsed * limit
                                    self.ul_tokens = min(self.ul_tokens, self.max_burst_kb)

                                # Consume tokens
                                self.ul_tokens -= size_kb
                                self.last_ul_time = now
                            else:
                                now = time.time()
                                elapsed = now - self.last_dl_time

                                # Add tokens based on elapsed time
                                self.dl_tokens += elapsed * limit
                                self.dl_tokens = min(self.dl_tokens, self.max_burst_kb)

                                # Check if we need to wait
                                if self.dl_tokens < size_kb:
                                    needed = size_kb - self.dl_tokens
                                    sleep_time = needed / limit
                                    time.sleep(sleep_time)
                                    # Update time after sleep
                                    now = time.time()
                                    elapsed = now - self.last_dl_time
                                    self.dl_tokens += elapsed * limit
                                    self.dl_tokens = min(self.dl_tokens, self.max_burst_kb)

                                # Consume tokens
                                self.dl_tokens -= size_kb
                                self.last_dl_time = now

                    # Send packet after rate limiting
                    w.send(packet)

                    # Update stats AFTER rate limiting for accurate measurement
                    with self.stats_lock:
                        if is_out:
                            self.ul_bytes_counted += size_kb
                        else:
                            self.dl_bytes_counted += size_kb
            except Exception:
                pass
            finally:
                if w is not None:
                    try:
                        w.close()
                    except:
                        pass

# --- Visual UI ---
class App(ctk.CTk):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        
        # Set dark mode theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.title("⚡ NetSpeed Control")
        self.geometry("320x480")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        
        # Handle Minimize and Close behaviors
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Main container with padding
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_label = ctk.CTkLabel(
            main_frame, 
            text="Network Speed Control", 
            font=("Segoe UI", 22, "bold"),
            text_color=("#2196F3", "#64B5F6")
        )
        header_label.pack(pady=(0, 25))
        
        # Download Section Frame
        dl_frame = ctk.CTkFrame(main_frame, corner_radius=15, fg_color=("#1a1a1a", "#2b2b2b"))
        dl_frame.pack(fill="x", pady=(0, 20))
        
        # Download Header
        dl_header = ctk.CTkFrame(dl_frame, fg_color="transparent")
        dl_header.pack(fill="x", padx=20, pady=(15, 5))
        
        dl_icon = ctk.CTkLabel(dl_header, text="⬇", font=("Segoe UI", 28))
        dl_icon.pack(side="left", padx=(0, 10))
        
        dl_title_frame = ctk.CTkFrame(dl_header, fg_color="transparent")
        dl_title_frame.pack(side="left", fill="x", expand=True)
        
        self.dl_label = ctk.CTkLabel(
            dl_title_frame, 
            text="Download", 
            font=("Segoe UI", 16, "bold"),
            anchor="w"
        )
        self.dl_label.pack(anchor="w")
        
        self.dl_limit_label = ctk.CTkLabel(
            dl_title_frame,
            text="Unlimited",
            font=("Segoe UI", 11),
            text_color=("#888888", "#aaaaaa"),
            anchor="w"
        )
        self.dl_limit_label.pack(anchor="w")
        
        # Download Speed Display
        self.dl_live_label = ctk.CTkLabel(
            dl_frame,
            text="0.0 KB/s",
            font=("Segoe UI", 32, "bold"),
            text_color=("#2196F3", "#64B5F6")
        )
        self.dl_live_label.pack(pady=(10, 15))
        
        # Download Slider
        self.dl_slider = ctk.CTkSlider(
            dl_frame,
            from_=0,
            to=30000,
            command=self.set_dl,
            height=20,
            button_color=("#2196F3", "#64B5F6"),
            button_hover_color=("#1976D2", "#42A5F5"),
            progress_color=("#2196F3", "#64B5F6")
        )
        self.dl_slider.set(0)
        self.dl_slider.pack(padx=20, pady=(0, 20), fill="x")
        
        # Upload Section Frame
        ul_frame = ctk.CTkFrame(main_frame, corner_radius=15, fg_color=("#1a1a1a", "#2b2b2b"))
        ul_frame.pack(fill="x")
        
        # Upload Header
        ul_header = ctk.CTkFrame(ul_frame, fg_color="transparent")
        ul_header.pack(fill="x", padx=20, pady=(15, 5))
        
        ul_icon = ctk.CTkLabel(ul_header, text="⬆", font=("Segoe UI", 28))
        ul_icon.pack(side="left", padx=(0, 10))
        
        ul_title_frame = ctk.CTkFrame(ul_header, fg_color="transparent")
        ul_title_frame.pack(side="left", fill="x", expand=True)
        
        self.ul_label = ctk.CTkLabel(
            ul_title_frame,
            text="Upload",
            font=("Segoe UI", 16, "bold"),
            anchor="w"
        )
        self.ul_label.pack(anchor="w")
        
        self.ul_limit_label = ctk.CTkLabel(
            ul_title_frame,
            text="Unlimited",
            font=("Segoe UI", 11),
            text_color=("#888888", "#aaaaaa"),
            anchor="w"
        )
        self.ul_limit_label.pack(anchor="w")
        
        # Upload Speed Display
        self.ul_live_label = ctk.CTkLabel(
            ul_frame,
            text="0.0 KB/s",
            font=("Segoe UI", 32, "bold"),
            text_color=("#4CAF50", "#81C784")
        )
        self.ul_live_label.pack(pady=(10, 15))
        
        # Upload Slider
        self.ul_slider = ctk.CTkSlider(
            ul_frame,
            from_=0,
            to=10000,
            command=self.set_ul,
            height=20,
            button_color=("#4CAF50", "#81C784"),
            button_hover_color=("#388E3C", "#66BB6A"),
            progress_color=("#4CAF50", "#81C784")
        )
        self.ul_slider.set(0)
        self.ul_slider.pack(padx=20, pady=(0, 20), fill="x")

        self.tray_icon = None
        self.is_minimized_to_tray = False
        
        # Override iconify to hide to tray instead
        self.bind("<Unmap>", self.on_window_state_change)
        
        # Start packet loop immediately for stats collection
        threading.Thread(target=self.manager._packet_loop, daemon=True).start()
        self.refresh_live_stats()

    def set_dl(self, val):
        self.manager.dl_limit = int(val)
        if self.manager.dl_limit > 0:
            self.dl_limit_label.configure(text=f"Limited to {self.manager.dl_limit} KB/s")
        else:
            self.dl_limit_label.configure(text="Unlimited")
        self.manager.update_limiting_state()

    def set_ul(self, val):
        self.manager.ul_limit = int(val)
        if self.manager.ul_limit > 0:
            self.ul_limit_label.configure(text=f"Limited to {self.manager.ul_limit} KB/s")
        else:
            self.ul_limit_label.configure(text="Unlimited")
        self.manager.update_limiting_state()

    def toggle_auto_disable(self, value):
        # value will be True/False depending on switch state
        # Removed: UI toggle no longer exists. This method kept for compatibility but does nothing.
        return

    def refresh_live_stats(self):
        # Thread-safe stats reading and reset
        with self.manager.stats_lock:
            dl_val = self.manager.dl_bytes_counted
            ul_val = self.manager.ul_bytes_counted
            self.manager.dl_bytes_counted = 0
            self.manager.ul_bytes_counted = 0
        
        # Format with appropriate units
        dl_text = f"{dl_val:.1f} KB/s" if dl_val < 1000 else f"{dl_val/1000:.2f} MB/s"
        ul_text = f"{ul_val:.1f} KB/s" if ul_val < 1000 else f"{ul_val/1000:.2f} MB/s"
        
        self.dl_live_label.configure(text=dl_text)
        self.ul_live_label.configure(text=ul_text)
        self.after(1000, self.refresh_live_stats)

    # --- Tray & Window Logic ---
    def create_icon_image(self, color="#3498db"):
            # Creates a circle icon with a dynamic color
            image = Image.new('RGB', (64, 64), (30, 30, 30))
            dc = ImageDraw.Draw(image)
            dc.ellipse([10, 10, 54, 54], fill=color)
            return image
            
    def update_tray_loop(self):
            toggle = False
            while self.manager.is_running:
                # If tray_icon was stopped or set to None by maximize_window, exit loop
                if self.tray_icon is None:
                    break
                    
                try:
                    if self.manager.dl_limit > 0 or self.manager.ul_limit > 0:
                        current_color = "#e67e22" if toggle else "#3498db"
                        self.tray_icon.icon = self.create_icon_image(current_color)
                        toggle = not toggle
                    else:
                        # Reset to blue if limits are 0
                        self.tray_icon.icon = self.create_icon_image("#3498db")
                except Exception:
                    # If the tray crashes, this prevents the whole app from dying
                    break
                    
                time.sleep(0.8)

    def on_window_state_change(self, event=None):
        # Detect minimize and hide to tray
        if self.state() == 'iconic' and not self.is_minimized_to_tray:
            self.is_minimized_to_tray = True
            self.withdraw()
            self.show_tray()

    def show_tray(self):
            if not self.tray_icon:
                menu = pystray.Menu(
                    pystray.MenuItem('Show', self.maximize_window, default=True),
                    pystray.MenuItem('Exit', self.on_close)
                )
                # Use the method that creates the blue circle by default
                self.tray_icon = pystray.Icon("NetLimiter", self.create_icon_image("#3498db"), "NetLimiter", menu)
                
                # Use daemon=True to ensure the thread dies when the app closes
                threading.Thread(target=self.tray_icon.run, daemon=True).start()

                # Start the flashing logic after a small delay to ensure icon is live
                self.after(500, lambda: threading.Thread(target=self.update_tray_loop, daemon=True).start())

    def maximize_window(self, icon=None, item=None):
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self.is_minimized_to_tray = False
        self.after(0, self.deiconify)
        self.after(0, lambda: self.state('normal'))

    def on_close(self, icon=None, item=None):
        self.manager.is_running = False
        if self.tray_icon:
            self.tray_icon.stop()
        self.destroy()
        sys.exit(0)

if __name__ == "__main__":
    mgr = BandwidthManager()
    app = App(mgr)
    app.mainloop()