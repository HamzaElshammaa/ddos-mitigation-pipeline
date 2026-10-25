import json
import platform
import subprocess
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

SEVERITY_RATE = {"HIGH": 10, "MEDIUM": 100, "LOW": 500}

class TokenBucket:
    def __init__(self, rate_pps: int, capacity: int =None):
        self.rate = rate_pps
        self.capacity = capacity if capacity is not None else rate_pps * 10
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self.passed  = 0
        self.dropped = 0

    def consume(self, n=1) -> bool:
        now = time.monotonic()
        elapsed_time = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed_time * self.rate)
        self._last_refill = now
        if self._tokens >=n:
            self._tokens -= n
            self.passed += n
            return True
        self.dropped += 1
        return False
    def set_rate(self, new_rate: int):
        self.rate = new_rate
        self.capacity = new_rate * 10
        self._tokens = min(self._tokens, float(self.capacity))
    def to_dict(self) -> dict: #snapshot for dashboard JOSN export 
        return {
            "rate_pps": self.rate,
            "capacity": self.capacity,
            "tokens_remaining": round(self._tokens, 2),
            "fill_ratio": round(self._tokens / self.capacity, 3), 
            "passed": self.passed,
            "dropped": self.dropped,
        }
class IptablesManager:
    def __init__(self, dry_run: bool = None):
        #Auto-detect: dry_run=True on non-Liux, flase on linux
        if dry_run is None:
            dry_run = platform.system() != "Linux"
        self.dry_run = dry_run
        self.rules = [] #list of applied rules for tracking

    @staticmethod
    def rule_rate_limit(ip, proto, limit_pps):
        name = ip.replace(".", "_")
        proto_part = f"-p {proto} " if proto else ""
        return (f"iptables -A INPUT -s {ip} {proto_part}-m hashlimit "
                f"--hashlimit-above {limit_pps}/s --hashlimit-mode srcip "
                f"--hashlimit-name rl_{name} -j DROP")
    
    @staticmethod
    def rule_block_port(ip, proto, port):
        return (f"iptables -A INPUT -s {ip} -p {proto} --dport {port} -j DROP")
    
    @staticmethod
    def rule_block_ip(ip):
        return (f"iptables -A INPUT -s {ip} -j DROP")
    
    @staticmethod
    def rule_whitelist_ip(ip):
        return (f"iptables -I INPUT 1 -s {ip} -j ACCEPT")
    
    @staticmethod
    def rule_unblock_ip(ip):
        return (f"iptables -D INPUT -s {ip} -j DROP")
    
    def flush_ip_rules(self, ip: str):
        if self.dry_run or platform.system() != "Linux":
            return
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "--line-numbers", "-n"],
            capture_output=True, text=True
        )
        lines_to_delete = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3] == ip:
                if parts[0].isdigit():
                    lines_to_delete.append(int(parts[0]))
        for num in sorted(lines_to_delete, reverse=True):
            subprocess.run(["iptables", "-D", "INPUT", str(num)], capture_output=True)
        if lines_to_delete:
            print(f"[iptables FLUSH] Removed {len(lines_to_delete)} existing rule(s) for {ip}")

    def apply(self, cmd, description, ip, rule_type):
        executed = False
        error = None
        if not self.dry_run and platform.system() == "Linux":
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            executed = result.returncode == 0
            error = result.stderr.strip() if result.returncode != 0 else None
        record = {
            "command": cmd,
            "description": description,
            "ip": ip,
            "rule_type": rule_type,
            "timestamp": datetime.now().isoformat(),
            "executed": executed,
            "dry_run": self.dry_run,
                "error": error
            }
        self.rules.append(record)
        if self.dry_run:
            print(f"[iptables DRY-RUN] {cmd}")
        elif executed:
            print(f"[iptables OK] {cmd}")
        else:
            print(f"[iptables ERROR] {cmd}")
        return record

class MitigationEngine:
    def __init__(self, output_dir: str = "mitigation_outputs", dry_run: bool = None ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.iptables= IptablesManager(dry_run=dry_run)
        self.rate_limiters = {}     # ip -> TokenBucket
        self.escalation_state = {}  # ip → current level (1/2/3)
        self.mitigation_log = []    # chronological action history
        self.whitelist = set()
        self.blacklist = set()
        self._load_list("whitelist.json", self.whitelist)
        self._load_list("blacklist.json", self.blacklist)


    def _load_list(self, filename, target_set):
        path = self.output_dir / filename
        if path.exists():
            with open(path) as f:
                target_set.update(json.load(f))
    
    def _save_list(self, filename, source_set):
        path = self.output_dir / filename
        with open(path, "w") as f:
            json.dump(sorted(source_set), f, indent=2)

    def _rate_limit(self,ip,proto,score,severity):
        rate = SEVERITY_RATE.get(severity, 100)
        if ip not in self.rate_limiters:
            self.rate_limiters[ip] = TokenBucket(rate_pps=rate)  # default starting rate
        else:
            # Adjust rate based on severity (example: more severe → lower rate)
            self.rate_limiters[ip].set_rate(rate)
        cmd = self.iptables.rule_rate_limit(ip, proto, rate)
        self.iptables.apply(cmd, f"Rate-limit {ip} to {rate}pps", ip, "rate_limit")
        self._log(ip,"rate_limit", score, severity, f"capped at {rate}pps")
        self.escalation_state[ip] = max(self.escalation_state.get(ip, 0), 1)  # move to level 1 or stay higher

    def _block_port(self, ip, proto, port, score, severity):
        cmd = self.iptables.rule_block_port(ip, proto or "tcp", port)
        self.iptables.apply(cmd, f"Block port {port} from ip {ip}", ip, "port_block")
        self._log(ip,"port_block", score, severity, f"port {port} blocked")
        self.escalation_state[ip] = max(self.escalation_state.get(ip, 0 ), 2)  # move to level 2 or stay higher

    def _block_ip(self, ip, score, severity, reason="escalation"):
        cmd = self.iptables.rule_block_ip(ip)
        self.iptables.apply(cmd, f"Block IP {ip} ({reason})", ip, "ip_block")
        self._log(ip, "ip_block", score, severity, reason)
        self.escalation_state[ip] = max(self.escalation_state.get(ip, 0), 3)  # move to level 3 or stay higher
    
    def _log(self, ip, action, score, severity, detail=""):
      self.mitigation_log.append({
          "timestamp": datetime.now().isoformat(),
          "ip":        ip,
          "action":    action,
          "score":     score,
          "severity":  severity,
          "detail":    detail,
      })    

    def process_alert(self, alert: dict, source_ip: str = None, attack_port: int = None):
        score = float(alert.get("peak_score", alert.get("score", 0)))
        severity = alert.get("severity", "MEDIUM")
        attack_type = alert.get("attack_type", "unknown_DDoS")

        #Determine Protocl from attack type
        proto = "tcp" if "SYN" in attack_type else "udp" if "UDP" in attack_type else None

        #No Source IP - Store generic rule fom alerts.json and return
        if not source_ip:
            generic = alert.get("firewall_rule", "")
            if generic:
                self.iptables.rules.append({
                    "command": generic, "description": "generic (no source IP)",
                    "ip": "N/A", "rule_type": "generic",
                    "timestamp": datetime.now().isoformat(),
                    "executed": False, "dry_run": True, "error": None
                })
            return

        #Blacklsit check - immediate full block
        if source_ip in self.blacklist:
            self._block_ip(source_ip, score, severity, reason="blacklist")
            return
        #whitelist check - skip all mitigations
        if source_ip in self.whitelist:
            self._log(source_ip, "skipped", score, severity, "whitelisted")
            return

        if score >= 6.0:
            self._rate_limit(source_ip, proto, score, severity)
            if attack_port:
                self._block_port(source_ip, proto, attack_port, score, severity)
            self._block_ip(source_ip, score, severity)
        elif score >= 4.0:
            self._rate_limit(source_ip, proto, score, severity)
            if attack_port:
                self._block_port(source_ip, proto, attack_port, score, severity)
        elif score >= 2.5:
            self._rate_limit(source_ip, proto, score, severity)

        
    def process_alerts_file(self, alerts_path: str, windows_path: str = None):
        with open(alerts_path) as f:
            alerts = json.load(f)

        print(f"\n[mitigation] Processing {len(alerts)} alerts...")
        for alert in alerts:
            # top_source_ip and top_destination_port are now embedded in each alert
            ip = alert.get("top_source_ip") or None
            if ip == "":
                ip = None
            port_raw = alert.get("top_destination_port")
            try:
                port = int(port_raw) if port_raw else None
            except (ValueError, TypeError):
                port = None
            self.process_alert(alert, source_ip=ip, attack_port=port)

        self.save_state()
        print(f"[mitigation] Done. Rules generated: {len(self.iptables.rules)}")

    def save_state(self):
            out = self.output_dir

            with open(out / "active_rules.json", "w") as f:
                json.dump(self.iptables.rules, f, indent=2)
            with open(out / "mitigation_log.json", "w") as f:
                json.dump(self.mitigation_log, f , indent=2)
            with open(out / "rate_limiters.json", "w") as f:
                json.dump({ip: tb.to_dict() for ip, tb in self.rate_limiters.items()}, f, indent=2)
            
            levels = {1: [], 2: [], 3: []}
            for ip, lvl in self.escalation_state.items():
                if lvl in levels:
                    levels[lvl].append(ip)
            
            with open(out / "mitigation_summary.json", "w") as f:
                json.dump({
                    "total_rules": len(self.iptables.rules),
                    "level_1_ips": levels[1],
                    "level_2_ips": levels[2],
                    "level_3_ips": levels[3],
                    "whitelist": sorted(self.whitelist),
                    "blacklist": sorted(self.blacklist),

                }, f, indent=2)
                
    def add_whitelist(self, ip: str):
        self.blacklist.discard(ip)
        self._save_list("blacklist.json", self.blacklist)
        self.iptables.flush_ip_rules(ip)
        self.whitelist.add(ip)
        self._save_list("whitelist.json", self.whitelist)
        cmd = self.iptables.rule_whitelist_ip(ip)
        self.iptables.apply(cmd, f"Whitelist {ip}", ip, "whitelist")
        self.save_state()

    def remove_whitelist(self, ip: str):
        self.whitelist.discard(ip)
        self._save_list("whitelist.json", self.whitelist)
        self.iptables.flush_ip_rules(ip)
        self.save_state()

    def add_blacklist(self, ip: str):
        self.whitelist.discard(ip)
        self._save_list("whitelist.json", self.whitelist)
        self.iptables.flush_ip_rules(ip)
        self.blacklist.add(ip)
        self._save_list("blacklist.json", self.blacklist)
        self._block_ip(ip, score=0, severity="HIGH", reason="blacklist")
        self.save_state()

    def remove_blacklist(self, ip: str):
        self.blacklist.discard(ip)
        self._save_list("blacklist.json", self.blacklist)
        self.iptables.flush_ip_rules(ip)
        self.save_state()

    def get_active_rules(self):
      return self.iptables.rules

    def get_mitigation_log(self):
      return self.mitigation_log

    def get_rate_limiter_state(self):
      return {ip: tb.to_dict() for ip, tb in self.rate_limiters.items()}

    def get_whitelist(self):
      return sorted(self.whitelist)

    def get_blacklist(self):
      return sorted(self.blacklist)


def main():
      import argparse

      parser = argparse.ArgumentParser(description="DDoS Mitigation Engine")
      sub = parser.add_subparsers(dest="command")

      # --- run subcommand ---
      run_p = sub.add_parser("run", help="Process alerts and apply mitigation rules")
      run_p.add_argument("--alerts",  required=True, help="Path to detection_outputs/alerts.json")
      run_p.add_argument("--windows", default=None,  help="Path to baseline_outputs/all_monitoring_windows.csv")
      run_p.add_argument("--output",  default="mitigation_outputs")
      run_p.add_argument("--no-dry-run", action="store_true", help="Actually execute iptables (Linux only)")

      # --- whitelist subcommand ---
      wl_p = sub.add_parser("whitelist", help="Manage whitelisted IPs")
      wl_p.add_argument("--add",    nargs="+", default=[])
      wl_p.add_argument("--remove", nargs="+", default=[])
      wl_p.add_argument("--list",   action="store_true")
      wl_p.add_argument("--output", default="mitigation_outputs")

      # --- blacklist subcommand ---
      bl_p = sub.add_parser("blacklist", help="Manage blacklisted IPs")
      bl_p.add_argument("--add",    nargs="+", default=[])
      bl_p.add_argument("--remove", nargs="+", default=[])
      bl_p.add_argument("--list",   action="store_true")
      bl_p.add_argument("--output", default="mitigation_outputs")

      args = parser.parse_args()

      if args.command == "run":
          dry_run = False if args.no_dry_run else None
          engine = MitigationEngine(output_dir=args.output, dry_run=dry_run)
          engine.process_alerts_file(args.alerts, args.windows)

      elif args.command in ("whitelist", "blacklist"):
          engine = MitigationEngine(output_dir=args.output)
          is_wl = args.command == "whitelist"
          for ip in args.add:
              engine.add_whitelist(ip) if is_wl else engine.add_blacklist(ip)
          for ip in args.remove:
              engine.remove_whitelist(ip) if is_wl else engine.remove_blacklist(ip)
          if args.list:
              items = engine.get_whitelist() if is_wl else engine.get_blacklist()
              print(f"\n{args.command.upper()}:")
              for ip in items:
                  print(f"  {ip}")

      else:
          parser.print_help()


if __name__ == "__main__":
    main()


    
        


    



