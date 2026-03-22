import subprocess
import psutil
import os
import signal
import time
import sys
import re
from collections import deque
from datetime import datetime, timedelta

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Button, RichLog, Label, Sparkline, ProgressBar

# Check for root
if os.geteuid() != 0:
    print("\n[!] ACCESS DENIED: Administrative Privileges Required")
    print("-" * 50)
    print("REASON 1: Hardware telemetry (Fan/Temp) requires kernel-level access.")
    print("REASON 2: Security scanners must access protected /root and /etc directories.")
    print("REASON 3: DNF package management requires root to install/update tools.")
    print("-" * 50)
    print(f"FIX: Please run using: sudo python3 {sys.argv[0]}\n")
    sys.exit(1)

# --------------------------------------------------------------------------------
# COMPONENT: TELEMETRY
# --------------------------------------------------------------------------------
class TelemetryPanel(Vertical):
    def compose(self) -> ComposeResult:
        self.border_title = "LIVE MONITORING"
        self.history = {k: deque([0.0] * 30, maxlen=30) for k in ["cpu", "ram", "disk", "temp", "fan"]}
        
        yield Label("CPU Usage: 0%", id="lbl_cpu", classes="stat-label")
        yield Sparkline(id="spark_cpu")
        yield Label("RAM Usage: 0%", id="lbl_ram", classes="stat-label")
        yield Sparkline(id="spark_ram")
        yield Label("Root Disk: 0%", id="lbl_disk", classes="stat-label")
        yield Sparkline(id="spark_disk")
        yield Label("CPU Temp: 0°C", id="lbl_temp", classes="stat-label")
        yield Sparkline(id="spark_temp")
        yield Label("Fan Speed: 0 RPM", id="lbl_fan", classes="stat-label")
        yield Sparkline(id="spark_fan")

    def update_metrics(self, cpu, ram, disk, temp, fan):
        metrics = {"cpu": cpu, "ram": ram, "disk": disk, "temp": temp, "fan": fan}
        for key, val in metrics.items():
            self.history[key].append(val)
            self.query_one(f"#spark_{key}", Sparkline).data = list(self.history[key])
        
        self.query_one("#lbl_cpu").update(f"CPU: [cyan]{cpu}%[/]")
        self.query_one("#lbl_ram").update(f"RAM: [cyan]{ram}%[/]")
        self.query_one("#lbl_disk").update(f"Disk: [cyan]{disk}%[/]")
        self.query_one("#lbl_fan").update(f"Fan: [cyan]{int(fan)} RPM[/]")
        t_color = "red" if temp > 80 else "yellow" if temp > 65 else "green"
        self.query_one("#lbl_temp").update(f"Temp: [{t_color}]{temp}°C[/]")

# --------------------------------------------------------------------------------
# COMPONENT: PROGRESS
# --------------------------------------------------------------------------------
class ProgressPanel(Vertical):
    def compose(self) -> ComposeResult:
        self.border_title = "ACTIVE PROCESS"
        yield Label("Idle", id="prog-status")
        yield ProgressBar(total=100, show_eta=False, id="pbar")
        # Detailed stats label
        yield Label("Ready to scan...", id="prog-details", classes="small-font")

    def reset(self):
        self.query_one("#pbar").progress = 0
        self.query_one("#prog-status").update("Idle")
        self.query_one("#prog-details").update("Waiting for next operation...")

# --------------------------------------------------------------------------------
# MAIN APP
# --------------------------------------------------------------------------------
class SecurityDashboard(App):
    CSS = """
    * { background: #000000; color: #ffffff; }
    #sidebar { width: 35; border-right: vkey $primary; padding: 1 2; }
    #main-view { width: 1fr; }
    #event-log { height: 1fr; border: round $secondary; margin: 0 1; }
    ProgressPanel { height: 8; border: round $accent; margin: 0 1; padding: 1; }
    #raw-log { height: 4fr; border: round $primary; margin: 0 1; }
    #warn-log { height: 2fr; border: round $error; margin: 0 1; }
    TelemetryPanel { height: auto; margin-top: 1; border: round $primary; padding: 0 1; }
    .stat-label { text-style: bold; margin-top: 1; }
    Sparkline { height: 1; color: $primary; }
    Button { width: 100%; margin-top: 1; text-style: bold; }
    .small-font { color: #888888; text-style: dim; }
    """

    def __init__(self):
        super().__init__()
        self.current_proc = None
        self.threat_count = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("[bold]SYSTEM OPERATIONS[/]", id="title")
                yield Button("Update Databases", id="btn_update", variant="primary")
                yield Button("Quick Scan (ClamAV)", id="btn_quick", variant="warning")
                yield Button("Deep Scan (ClamAV)", id="btn_deep", variant="warning")
                yield Button("System Check (RKHunter)", id="btn_rkhunter", variant="warning")
                yield Button("Combo Scan (Both)", id="btn_combo", variant="success")
                yield Button("🛑 Cancel Operation", id="btn_cancel", variant="error", disabled=True)
                yield Button("Quit", id="btn_exit")
                yield TelemetryPanel()

            with Vertical(id="main-view"):
                self.event_log = RichLog(id="event-log", markup=True)
                self.progress_pane = ProgressPanel()
                self.raw_log = RichLog(id="raw-log", markup=True)
                self.warn_log = RichLog(id="warn-log", markup=True)
                yield self.event_log; yield self.progress_pane
                yield self.raw_log; yield self.warn_log
        yield Footer()

    def on_mount(self) -> None:
        self.event_log.border_title = "SYSTEM EVENTS"
        self.raw_log.border_title = "SCANNER STREAM"
        self.warn_log.border_title = "THREATS & WARNINGS"
        self.log_event("[bold cyan]Dashboard Ready.[/]")
        self.set_interval(1.0, self.refresh_telemetry)

    def log_event(self, msg):
        self.event_log.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def refresh_telemetry(self):
        try:
            cpu = psutil.cpu_percent(); ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            t_data = psutil.sensors_temperatures()
            temp = 0.0
            for k in ['thinkpad', 'coretemp', 'acpitz']:
                if k in t_data and t_data[k]: temp = t_data[k][0].current; break
            f_data = psutil.sensors_fans()
            fan = f_data['thinkpad'][0].current if 'thinkpad' in f_data else 0.0
            self.query_one(TelemetryPanel).update_metrics(cpu, ram, disk, temp, fan)
        except: pass

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn_exit": self.exit()
        elif bid == "btn_cancel": self.abort_task()
        elif bid == "btn_update": self.run_update()
        elif bid == "btn_quick": self.run_quick_scan()
        elif bid == "btn_deep": self.run_deep_scan()
        elif bid == "btn_rkhunter": self.run_rkhunter()
        elif bid == "btn_combo": self.run_combo()

    def run_update(self):
        self.log_event("🔄 Updating Databases...")
        self.execute_worker("freshclam && rkhunter --update", "DB Update", 100)

   # --- HELPER: AUTO-INSTALL / UPDATE  ---
    def ensure_package(self, binary: str, package_name: str, friendly_name: str):
        """Checks if a tool is installed. If not, installs it. If old, updates it."""
        self.log_event(f"Checking your {friendly_name} installation...")
        
        # Check if binary exists
        check = subprocess.run(f"which {binary}", shell=True, capture_output=True)
        
        if check.returncode != 0:
            self.log_event(f"[bold yellow][!][/] {friendly_name} is not installed. Installing now...")
            subprocess.run(f"dnf install -y {package_name}", shell=True, capture_output=True)
            self.log_event(f"[bold green][V][/] {friendly_name} installed successfully.")
        else:
            # Optional: Try to update
            self.log_event(f"Updating {friendly_name} to latest version...")
            subprocess.run(f"dnf update -y {package_name}", shell=True, capture_output=True)
            self.log_event(f"[bold green][V][/] {friendly_name} is up to date.")

    # --- UPDATED BUTTON FUNCTIONS ---

    def run_quick_scan(self):
        self.ensure_package("clamscan", "clamav clamav-update", "ClamAV")
        self.log_event("⚡ Quick Scan Started (Critical areas only).")
        cmd = "clamscan -r --max-filesize=50M --max-scantime=10000 /home /etc /tmp"
        self.execute_worker(cmd, "Quick Scan", 15000)

    def run_deep_scan(self):
        self.ensure_package("clamscan", "clamav clamav-update", "ClamAV")
        self.log_event("🔍 Deep Scan Started (Full System).")
        cmd = "clamscan -r --exclude-dir='^/sys|^/proc|^/dev|^/run' /"
        self.execute_worker(cmd, "Deep Scan", 250000)

    def run_rkhunter(self):
        self.ensure_package("rkhunter", "rkhunter", "RKHunter")
        self.log_event("🛡️ RKHunter Started.")
        cmd = "rkhunter -c --sk --nocolors"
        self.execute_worker(cmd, "RKHunter", 160)

    def run_combo(self):
        # Check both before starting
        self.ensure_package("rkhunter", "rkhunter", "RKHunter")
        self.ensure_package("clamscan", "clamav", "ClamAV")
        
        self.log_event("🚀 Combo Scan Triggered (RKHunter + ClamAV).")
        # Chaining them together
        cmd = "clamscan -r /home /etc /tmp && rkhunter -c --sk --nocolors"
        self.execute_worker(cmd, "Combo Scan", 20000)    
        
    def abort_task(self):
        if self.current_proc:
            os.killpg(os.getpgid(self.current_proc.pid), signal.SIGTERM)
            self.log_event("[bold red]!! Process Terminated.[/]")

    @work(exclusive=True, thread=True)
    def execute_worker(self, cmd, name, est):        
        self.call_from_thread(self.query_one, "#btn_cancel", Button).disabled = False
        self.call_from_thread(self.query_one, "#prog-status", Label).update(f"Process: [bold cyan]{name}[/]")
        self.call_from_thread(self.query_one, "#pbar", ProgressBar).total = est
        self.call_from_thread(self.query_one, "#pbar", ProgressBar).progress = 0
        
        start_time = time.time()
        start_str = datetime.now().strftime('%H:%M:%S')
        count = 0
        self.threat_count = 0
        
        self.current_proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, preexec_fn=os.setsid
        )

        for line in iter(self.current_proc.stdout.readline, ""):
            if line:
                count += 1
                clean = line.strip()
                
                # Update progress UI
                self.call_from_thread(self.query_one, "#pbar", ProgressBar).progress = count
                
                if count % 15 == 0:
                    elap = time.time() - start_time
                    speed = count / elap if elap > 0 else 0
                    eta_secs = int((est - count) / speed) if speed > 0 else 0
                    eta_str = str(timedelta(seconds=max(0, eta_secs)))
                    elap_str = str(timedelta(seconds=int(elap)))
                    
                    stats = (f"Scanned: {count}/{est} | ETA: {eta_str} | "
                             f"Speed: {speed:.1f} it/s | Threats: [bold red]{self.threat_count}[/] | "
                             f"Started: {start_str} | Elapsed: {elap_str}")
                    self.call_from_thread(self.query_one, "#prog-details", Label).update(stats)
                
                # Raw log
                if not clean.endswith(" OK"): 
                    self.call_from_thread(self.raw_log.write, clean)
                
                # Threat detection
                if any(k in clean for k in ["FOUND", "Warning", "Infected", "SUSPICIOUS"]):
                    self.threat_count += 1
                    self.call_from_thread(self.warn_log.write, f"[bold red]!! {clean}[/]")

        self.current_proc.wait()
        self.current_proc = None
        
        self.call_from_thread(self.query_one, "#btn_cancel", Button).disabled = True
        self.call_from_thread(self.progress_pane.reset) 
        self.call_from_thread(self.log_event, f"[bold green]✓ {name} Finished. Threats found: {self.threat_count}[/]")

if __name__ == "__main__":
    SecurityDashboard().run()