#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco Top-Secret Config Sanitizer v3

Modes:
  standard – hard ano
  max      – paranoik mode max anonim
  
How it works:
Takes a running-config (or similar Cisco config) and outputs a dummy config that’s safe to share with AI or anyone else.
"""

import re
import sys
import ipaddress
import hashlib
import random
from typing import Dict, List


# =====================================================================
# CONFIG
# =====================================================================

# salt
DEFAULT_IP_SALT = "CHANGE_THIS_SALT_TO_YOUR_OWN_SECRET"


# =====================================================================
# HELPER: deterministic fake IP mapping
# =====================================================================

def map_ipv4(ip: str, salt: str) -> str:
    """Map real IPv4 to deterministic fake 10.X.Y.Z based on SHA256 + salt."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ip  # not a real IP
    h = hashlib.sha256((salt + ip).encode("utf-8")).digest()
    o2 = (h[0] % 254) + 1
    o3 = (h[1] % 254) + 1
    o4 = (h[2] % 254) + 1
    return f"10.{o2}.{o3}.{o4}"


def map_ipv6(ip: str, salt: str) -> str:
    """Map real IPv6 to deterministic fake in 2001:db8::/32 (documentation prefix)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 6:
            return ip
    except ValueError:
        return ip

    h = hashlib.sha256((salt + ip).encode("utf-8")).digest()
    parts = []
    for i in range(0, 12, 2):
        val = (h[i] << 8) | h[i + 1]
        parts.append(f"{val:04x}")
    return "2001:db8:" + ":".join(parts) + "::"


# =====================================================================
# SANITIZER CLASS
# =====================================================================

class CiscoSanitizer:
    def __init__(self, mode: str = "standard", ip_salt: str = DEFAULT_IP_SALT):
        self.mode = mode.lower()
        if self.mode not in ("standard", "max"):
            raise ValueError("mode must be 'standard' or 'max'")
        self.ip_salt = ip_salt

        # Maps to keep structure but anonymize identifiers
        self.user_map: Dict[str, str] = {}
        self.vlan_map: Dict[str, str] = {}
        self.acl_map: Dict[str, str] = {}
        self.prefix_list_map: Dict[str, str] = {}
        self.object_counter = {
            "user": 1,
            "vlan": 1001,
            "acl": 1,
            "pfx": 1,
            "device": 1,
        }

    # ------------------ generic mappers ------------------

    def _map_username(self, name: str) -> str:
        if name not in self.user_map:
            alias = f"user{self.object_counter['user']:02d}"
            self.user_map[name] = alias
            self.object_counter["user"] += 1
        return self.user_map[name]

    def _map_vlan(self, vlan_id: str) -> str:
        if vlan_id not in self.vlan_map:
            alias = str(self.object_counter["vlan"])
            self.vlan_map[vlan_id] = alias
            self.object_counter["vlan"] += 1
        return self.vlan_map[vlan_id]

    def _map_acl(self, name: str) -> str:
        if name not in self.acl_map:
            alias = f"ACL_REDACTED_{self.object_counter['acl']:02d}"
            self.acl_map[name] = alias
            self.object_counter["acl"] += 1
        return self.acl_map[name]

    def _map_prefix_list(self, name: str) -> str:
        if name not in self.prefix_list_map:
            alias = f"PFX_REDACTED_{self.object_counter['pfx']:02d}"
            self.prefix_list_map[name] = alias
            self.object_counter["pfx"] += 1
        return self.prefix_list_map[name]

    # ------------------ helpers ------------------

    def _sanitize_ipv4_in_line(self, line: str) -> str:
        """
        Жёсткая IPv4-зачистка:
        - ловим и голые IP, и IP/маска
        - не ломаем остальной текст
        """
        tokens = re.findall(r"\S+", line)
        for t in tokens:
            stripped = t.strip("(),;")
            ip_part = stripped.split("/", 1)[0]
            try:
                ipaddress.ip_address(ip_part)
            except ValueError:
                continue
            fake = map_ipv4(ip_part, self.ip_salt)
            line = line.replace(ip_part, fake)
        return line

    # ------------------ public entry ------------------

    def sanitize_and_optionally_shuffle(self, lines: List[str]) -> List[str]:
        """Full pipeline: line-level sanitize + (optionally) block shuffling & fake blocks."""
        # 1) Line-level sanitize
        sanitized_lines = [self.sanitize_line(l.rstrip("\n")) + "\n" for l in lines]

        if self.mode != "max":
            return sanitized_lines

        # 2) MAX MODE: block extraction, shuffling, fake blocks
        return self._apply_max_block_randomization(sanitized_lines)

    # ------------------ line sanitization ------------------

    def sanitize_line(self, line: str) -> str:
        original = line

        # 1) Crypto / keys / certificates – del
        if re.search(r"\b(crypto|certificate|pkcs12|trustpoint|key-string|rsa key)\b", line, re.I):
            return "<CRYPTO_REDACTED>"

        # 2) Secret hash all replace!
        line = re.sub(r"(\benable\s+secret)\b.*", r"\1 <SECRET_REDACTED>", line, flags=re.I)
        line = re.sub(r"(\benable\s+password)\b.*", r"\1 <PASSWORD_REDACTED>", line, flags=re.I)

        line = re.sub(r"(\bsecret)\b.*", r"\1 <SECRET_REDACTED>", line, flags=re.I)
        line = re.sub(r"(\bpassword)\b.*", r"\1 <PASSWORD_REDACTED>", line, flags=re.I)

        line = re.sub(r"(\bmd5)\b.*", r"\1 <HASH_REDACTED>", line, flags=re.I)
        line = re.sub(r"(\bencrypted)\b.*", r"\1 <HASH_REDACTED>", line, flags=re.I)

        # 3) SNMP communities, location, contact
        line = re.sub(r"(snmp-server\s+community)\s+.+", r"\1 <COMMUNITY_REDACTED>", line, flags=re.I)
        line = re.sub(r"(snmp-server\s+location)\s+.+", r"\1 <LOCATION_REDACTED>", line, flags=re.I)
        line = re.sub(r"(snmp-server\s+contact)\s+.+", r"\1 <CONTACT_REDACTED>", line, flags=re.I)

        # 4) Usernames
        m = re.search(r"^\s*username\s+(\S+)", line, flags=re.I)
        if m:
            real = m.group(1)
            fake = self._map_username(real)
            line = line.replace(real, fake, 1)

        # 5) Hostname
        if re.match(r"^\s*hostname\s+\S+", line, flags=re.I):
            device_id = self.object_counter["device"]
            self.object_counter["device"] += 1
            return f"hostname DEVICE-REDACTED-{device_id:02d}"

        # 5.1) Timezone
        if re.match(r"^\s*clock\s+timezone\b", line, flags=re.I):
            return "clock timezone <TZ_REDACTED> 0 0"

        # 5.2) Cisco IOS header (show version)
        if line.startswith("Cisco IOS Software"):
            return "Cisco IOS Software, <IOS_REDACTED>"

        # 6) MAC addresses (Cisco style xxxx.xxxx.xxxx)
        line = re.sub(
            r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b",
            "<MAC_REDACTED>",
            line,
            flags=re.I,
        )

        # 6.1) MAC в формате 00:11:22:33:44:55 или 00-11-22-33-44-55
        line = re.sub(
            r"\b[0-9a-f]{2}([:\-][0-9a-f]{2}){5}\b",
            "<MAC_REDACTED>",
            line,
            flags=re.I,
        )

        # 7) Serial numbers / PID / Model / SN
        line = re.sub(
            r"(System Serial Number:).*",
            r"\1 <SERIAL_REDACTED>",
            line,
            flags=re.I,
        )

        line = re.sub(
            r"(Processor board ID|Motherboard serial number|Chassis Serial Number"
            r"|Power supply serial number|System serial number"
            r"|Top Assembly Part Number|Top Assembly Revision Number"
            r"|Daughterboard serial number|Daughterboard assembly number"
            r"|Hardware Board Revision Number).*",
            r"\1 <SERIAL_REDACTED>",
            line,
            flags=re.I,
        )

        # SN: ... в show inventory
        line = re.sub(r"(SN:\s*)\S+", r"\1<SERIAL_REDACTED>", line, flags=re.I)

        # PID / Model number
        line = re.sub(r"(PID:\s*)\S+", r"\1<MODEL_REDACTED>", line, flags=re.I)
        line = re.sub(r"(Model number\s*:).*", r"\1 <MODEL_REDACTED>", line, flags=re.I)

        # "cisco <model> ..." (ограниченно)
        line = re.sub(r"^(cisco\s+)(\S+)", r"\1<MODEL_REDACTED>", line, flags=re.I)

        # 8) Emails
        line = re.sub(r"[\w\.-]+@[\w\.-]+\.[A-Za-z]{2,}", "<EMAIL_REDACTED>", line)

        # 9) Phone numbers (примерно)
        line = re.sub(r"\+?\d[\d\-\s]{6,}\d", "<PHONE_REDACTED>", line)

        # 10) Domains / FQDNs (corp.local, example.com)
        def _mask_domain(match):
            return "<DOMAIN_REDACTED>"

        line = re.sub(r"\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", _mask_domain, line)

        # 11) IPv4 (через helper)
        line = self._sanitize_ipv4_in_line(line)

        # 12) IPv6 (грубо)
        tokens = line.split()
        for t in tokens:
            if ":" in t:
                clean = t.strip(",;")
                try:
                    ip_obj = ipaddress.ip_address(clean)
                except ValueError:
                    continue
                if ip_obj.version == 6:
                    fake6 = map_ipv6(clean, self.ip_salt)
                    line = line.replace(clean, fake6)

        # 13) MAX MODE 
        if self.mode == "max":
            line = self._apply_max_mode_to_line(line)

        if line.strip() == "":
            return "! <REDACTED_EMPTY_LINE>"
        return line

    # ------------------ MAX MODE: per-line hardcore ------------------

    def _apply_max_mode_to_line(self, line: str) -> str:
        # Descriptions → REDACTED
        if re.search(r"\bdescription\b", line, flags=re.I):
            indent = re.match(r"^\s*", line).group(0)
            return indent + "description <REDACTED_DESC>"

        # VLAN remap (single)
        def _vlan_single(match):
            vid = match.group(1)
            new = self._map_vlan(vid)
            return match.group(0).replace(vid, new)

        line = re.sub(r"\bvlan\s+(\d+)\b", _vlan_single, line, flags=re.I)

        # trunk allowed vlan list
        def _vlan_list(match):
            orig_list = match.group(1)
            vids = re.split(r"[,\s]+", orig_list.strip())
            vids = [v for v in vids if v.isdigit()]
            mapped = [self._map_vlan(v) for v in vids]
            return "switchport trunk allowed vlan " + ",".join(mapped)

        line = re.sub(r"switchport trunk allowed vlan\s+([0-9,\s]+)", _vlan_list, line, flags=re.I)

        # ACL names in config
        line = re.sub(
            r"\bip access-list (standard|extended)\s+(\S+)",
            lambda m: f"ip access-list {m.group(1)} {self._map_acl(m.group(2))}",
            line,
            flags=re.I,
        )

        line = re.sub(
            r"(access-class\s+)(\S+)",
            lambda m: m.group(1) + self._map_acl(m.group(2)),
            line,
            flags=re.I,
        )

        line = re.sub(
            r"(ip access-group\s+)(\S+)",
            lambda m: m.group(1) + self._map_acl(m.group(2)),
            line,
            flags=re.I,
        )

        # ACL names in 'show access-lists'
        line = re.sub(
            r"^(Extended IP access list)\s+(\S+)",
            lambda m: f"{m.group(1)} {self._map_acl(m.group(2))}",
            line,
            flags=re.I,
        )

        line = re.sub(
            r"^(IPv6 access list)\s+(\S+)",
            lambda m: f"{m.group(1)} {self._map_acl(m.group(2))}",
            line,
            flags=re.I,
        )

        # Prefix-lists
        line = re.sub(
            r"(ip prefix-list\s+)(\S+)",
            lambda m: m.group(1) + self._map_prefix_list(m.group(2)),
            line,
            flags=re.I,
        )

        if line.strip().startswith("!"):
            return "! <COMMENT_REDACTED>"

        return line

    # ------------------ MAX MODE: block randomization ------------------

    def _apply_max_block_randomization(self, lines: List[str]) -> List[str]:
        """
        В max-режиме:
          - выдираем interface-блоки, ip access-list блоки, ip route строки
          - перемешиваем их
          - добавляем фейковые интерфейсы и ACL
          - собираем всё обратно
        """
        # determine salt:
        random.seed(hashlib.sha256(self.ip_salt.encode("utf-8")).digest())

        interfaces: List[List[str]] = []
        acls: List[List[str]] = []
        routes: List[str] = []
        used = set()  # index 

        # --- extract interface blocks ---
        i = 0
        n = len(lines)
        while i < n:
            if re.match(r"^\s*interface\s+\S+", lines[i], flags=re.I):
                start = i
                i += 1
                while i < n and not re.match(
                    r"^\s*(interface\s+|ip access-list\s+|router\s+|line\s+|end\b)",
                    lines[i],
                    flags=re.I,
                ):
                    i += 1
                end = i
                block = lines[start:end]
                interfaces.append(block)
                used.update(range(start, end))
            else:
                i += 1

        # --- extract ACL blocks ---
        i = 0
        while i < n:
            if re.match(r"^\s*ip access-list\s+", lines[i], flags=re.I):
                start = i
                i += 1
                while i < n and not re.match(
                    r"^\s*(ip access-list\s+|interface\s+|router\s+|line\s+|end\b)",
                    lines[i],
                    flags=re.I,
                ):
                    i += 1
                end = i
                block = lines[start:end]
                acls.append(block)
                used.update(range(start, end))
            else:
                i += 1

        # --- extract ip route lines ---
        for idx, line in enumerate(lines):
            if idx in used:
                continue
            if re.match(r"^\s*ip route\s+", line, flags=re.I) or re.match(r"^\s*ipv6 route\s+", line, flags=re.I):
                routes.append(line)
                used.add(idx)

        # --- keep "other" lines  ---
        others = [lines[idx] for idx in range(n) if idx not in used]

        # --- shuffle blocks ---
        random.shuffle(interfaces)
        random.shuffle(acls)
        random.shuffle(routes)

        # --- add fake interfaces & ACLs ---
        fake_blocks = self._generate_fake_blocks()

        new_lines: List[str] = []
        new_lines.append("! ==== SANITIZED & RANDOMIZED CONFIG (MAX MODE) ====\n")

        # others 
        new_lines.extend(others)

        # interfaces
        new_lines.append("\n! ==== INTERFACES (ORDER RANDOMIZED) ====\n")
        for block in interfaces:
            new_lines.extend(block)
        for block in fake_blocks["interfaces"]:
            new_lines.extend(block)

        # ACLs
        new_lines.append("\n! ==== ACCESS-LISTS (ORDER RANDOMIZED) ====\n")
        for block in acls:
            new_lines.extend(block)
        for block in fake_blocks["acls"]:
            new_lines.extend(block)

        # routes
        new_lines.append("\n! ==== ROUTES (ORDER RANDOMIZED) ====\n")
        for r in routes:
            new_lines.append(r)
        for r in fake_blocks["routes"]:
            new_lines.append(r)

        new_lines.append("\n! ==== END OF SANITIZED CONFIG ====\n")
        return new_lines

    # ------------------ MAX MODE: fake blocks ------------------

    def _generate_fake_blocks(self) -> Dict[str, List[List[str]]]:
        """Добавляем фейковые интерфейсы, ACL и маршруты, чтобы сбить отпечаток."""
        fake_interfaces: List[List[str]] = []
        fake_acls: List[List[str]] = []
        fake_routes: List[str] = []

        # Fake int
        for idx in range(2):
            iface_name = f"GigabitEthernet9/{idx}"
            vlan = 4000 + idx
            block = [
                f"interface {iface_name}\n",
                " description <FAKE_INTERFACE>\n",
                " switchport mode access\n",
                f" switchport access vlan {vlan}\n",
                " spanning-tree portfast\n",
                " shutdown\n",
                "!\n",
            ]
            fake_interfaces.append(block)

        # Fake ACL
        for idx in range(2):
            acl_name = f"ACL_FAKE_{idx+1:02d}"
            block = [
                f"ip access-list extended {acl_name}\n",
                " remark <FAKE_ACL_FOR_RANDOMIZATION>\n",
                " permit ip 10.255.0.0 0.0.255.255 any\n",
                " deny   ip any any log\n",
                "!\n",
            ]
            fake_acls.append(block)

        # fakae ip route
        fake_routes.append("ip route 10.250.0.0 255.255.0.0 10.0.0.1\n")
        fake_routes.append("ip route 198.18.0.0 255.254.0.0 10.0.0.2\n")

        return {"interfaces": fake_interfaces, "acls": fake_acls, "routes": fake_routes}


# =====================================================================
# CLI
# =====================================================================

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python cisco_sanitizer.py input.txt output.txt [--mode standard|max] [--salt YOUR_SALT] [--max]")
        print("Examples:")
        print("  python cisco_sanitizer.py run.txt safe.txt")
        print("  python cisco_sanitizer.py run.txt safe.txt --mode=max --salt=projectX")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    mode = "standard"
    ip_salt = DEFAULT_IP_SALT

    for arg in sys.argv[3:]:
        if arg.startswith("--mode"):
            parts = arg.split("=")
            if len(parts) == 2:
                mode = parts[1].strip()
        elif arg in ("--max", "--paranoid"):
            mode = "max"
        elif arg.startswith("--salt"):
            parts = arg.split("=")
            if len(parts) == 2:
                ip_salt = parts[1].strip()

    try:
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {input_path}")
        sys.exit(1)

    sanitizer = CiscoSanitizer(mode=mode, ip_salt=ip_salt)
    result = sanitizer.sanitize_and_optionally_shuffle(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(result)

    print(f"[+] Sanitization completed.")
    print(f"[+] Mode: {mode}")
    print(f"[+] Input:  {input_path}")
    print(f"[+] Output: {output_path}")
    print(f"[+] Salt:   {ip_salt}")
    if mode == "max":
        print("[!] Top-secret mode enabled: maximum anonymization + block randomization + fake objects.")


if __name__ == "__main__":
    main()

