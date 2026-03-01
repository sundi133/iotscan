"""Firmware analysis module - binary extraction, vulnerability scanning, hardcoded credential detection."""

from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

from ..base import BaseScanner
from ..models import Severity

# Common firmware magic bytes for header identification
FIRMWARE_SIGNATURES = {
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"\xd0\x0d\xfe\xed": "Device Tree Blob (FDT)",
    b"\x68\x73\x71\x73": "SquashFS (little-endian)",
    b"\x73\x71\x73\x68": "SquashFS (big-endian)",
    b"\x1f\x8b": "gzip compressed",
    b"\x42\x5a\x68": "bzip2 compressed",
    b"\xfd\x37\x7a\x58\x5a": "xz compressed",
    b"\x30\x37\x30\x37\x30\x31": "CPIO archive",
    b"\x89\x50\x4e\x47": "PNG image",
    b"\x7f\x45\x4c\x46": "ELF binary",
    b"\x50\x4b\x03\x04": "ZIP/APK archive",
}

# Patterns that indicate hardcoded secrets in firmware
SECRET_PATTERNS = [
    (r"password\s*[=:]\s*['\"]?[\w!@#$%^&*]{4,}['\"]?", "Hardcoded password"),
    (r"api[_-]?key\s*[=:]\s*['\"]?[\w\-]{16,}['\"]?", "Hardcoded API key"),
    (r"secret\s*[=:]\s*['\"]?[\w\-]{8,}['\"]?", "Hardcoded secret"),
    (r"token\s*[=:]\s*['\"]?[\w\-\.]{20,}['\"]?", "Hardcoded token"),
    (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "Embedded private key"),
    (r"(?:jdbc|mysql|postgres|mongodb)://\w+:\w+@", "Database connection string with credentials"),
    (r"AWS[_\s]?(?:ACCESS|SECRET)[_\s]?KEY\s*[=:]\s*\w+", "AWS credential"),
]

# Dangerous function patterns in extracted binaries
UNSAFE_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "vsprintf", "realpath", "getwd", "streadd",
    "strtrns", "mktemp",
]

# Known vulnerable library signatures
VULNERABLE_LIBS = {
    "busybox": {
        "pattern": rb"BusyBox v(\d+\.\d+\.\d+)",
        "min_safe": "1.36.0",
        "cve_prefix": "CVE-2022-48174",
    },
    "openssl": {
        "pattern": rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)",
        "min_safe": "3.0.0",
        "cve_prefix": "CVE-2023-0286",
    },
    "dropbear": {
        "pattern": rb"dropbear_(\d{4}\.\d+)",
        "min_safe": "2024.84",
        "cve_prefix": "CVE-2023-48795",
    },
    "lighttpd": {
        "pattern": rb"lighttpd/(\d+\.\d+\.\d+)",
        "min_safe": "1.4.70",
        "cve_prefix": "CVE-2023-37621",
    },
    "dnsmasq": {
        "pattern": rb"dnsmasq-(\d+\.\d+)",
        "min_safe": "2.90",
        "cve_prefix": "CVE-2023-28450",
    },
}


class FirmwareAnalyzer(BaseScanner):
    """Analyze IoT device firmware for vulnerabilities, secrets, and unsafe patterns."""

    name = "firmware_analysis"
    description = "Firmware binary extraction, vulnerability scanning, and hardcoded credential detection"

    def scan(self) -> None:
        firmware_path = self.target.firmware_path
        if not firmware_path:
            self.add_finding(
                title="No firmware path provided",
                severity=Severity.INFO,
                description="Firmware analysis requires a firmware binary path. Set target.firmware_path.",
            )
            return

        path = Path(firmware_path)
        if not path.exists():
            self.add_finding(
                title="Firmware file not found",
                severity=Severity.INFO,
                description=f"File not found: {firmware_path}",
            )
            return

        data = path.read_bytes()
        self.result.raw_data["file_size"] = len(data)
        self.result.raw_data["sha256"] = hashlib.sha256(data).hexdigest()
        self.result.raw_data["md5"] = hashlib.md5(data).hexdigest()

        self._identify_headers(data)
        self._scan_for_secrets(data)
        self._check_unsafe_functions(data)
        self._detect_vulnerable_libraries(data)
        self._check_elf_hardening(data)
        self._check_entropy_sections(data)
        self._check_debug_artifacts(data)
        self._check_crypto_issues(data)

    def _identify_headers(self, data: bytes) -> None:
        """Identify embedded filesystem and binary headers in firmware."""
        found_sections = []
        for offset in range(0, min(len(data), 4 * 1024 * 1024), 512):
            chunk = data[offset : offset + 8]
            for magic, name in FIRMWARE_SIGNATURES.items():
                if chunk.startswith(magic):
                    found_sections.append({"type": name, "offset": hex(offset)})

        self.result.raw_data["identified_sections"] = found_sections

        if not found_sections:
            self.add_finding(
                title="Unrecognized firmware format",
                severity=Severity.LOW,
                description="No known firmware headers detected. The binary may be encrypted or use a proprietary format.",
                remediation="Attempt manual analysis or use binwalk for deeper extraction.",
            )
        else:
            section_summary = ", ".join(f"{s['type']} at {s['offset']}" for s in found_sections[:10])
            self.add_finding(
                title="Firmware sections identified",
                severity=Severity.INFO,
                description=f"Found {len(found_sections)} embedded sections: {section_summary}",
            )

    def _scan_for_secrets(self, data: bytes) -> None:
        """Scan firmware binary for hardcoded credentials and secrets."""
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")

        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Redact actual values in evidence
                sanitized = [m[:20] + "..." if len(m) > 20 else m for m in matches[:5]]
                self.add_finding(
                    title=f"{label} found in firmware",
                    severity=Severity.CRITICAL if "private key" in label.lower() else Severity.HIGH,
                    description=f"Detected {len(matches)} instance(s) of {label} embedded in firmware binary.",
                    evidence=f"Sample matches (redacted): {sanitized}",
                    remediation="Remove hardcoded credentials. Use secure key storage (TPM/HSM) or provisioning mechanisms.",
                    owasp_iot="I1",
                    cvss_score=9.1 if "private key" in label.lower() else 7.5,
                )

    def _check_unsafe_functions(self, data: bytes) -> None:
        """Detect usage of memory-unsafe C functions in firmware binaries."""
        text = data.decode("latin-1", errors="ignore")
        found_unsafe = []
        for func in UNSAFE_FUNCTIONS:
            if func in text:
                found_unsafe.append(func)

        if found_unsafe:
            self.add_finding(
                title="Unsafe C functions detected in firmware",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(found_unsafe)} memory-unsafe functions: {', '.join(found_unsafe)}. "
                    "These may lead to buffer overflow vulnerabilities."
                ),
                evidence=f"Functions: {found_unsafe}",
                remediation="Replace with safer alternatives (strncpy, snprintf, fgets). Enable stack canaries and ASLR.",
            )

    def _detect_vulnerable_libraries(self, data: bytes) -> None:
        """Detect known vulnerable library versions in firmware."""
        for lib_name, info in VULNERABLE_LIBS.items():
            match = re.search(info["pattern"], data)
            if match:
                version = match.group(1).decode("utf-8", errors="ignore")
                self.add_finding(
                    title=f"Potentially vulnerable {lib_name} version detected",
                    severity=Severity.HIGH,
                    description=(
                        f"Found {lib_name} version {version}. "
                        f"Minimum recommended version: {info['min_safe']}."
                    ),
                    evidence=f"Detected version string: {match.group(0).decode('utf-8', errors='ignore')}",
                    remediation=f"Update {lib_name} to version {info['min_safe']} or later.",
                    cve=info["cve_prefix"],
                    owasp_iot="I5",
                    cvss_score=7.5,
                )

    def _check_entropy_sections(self, data: bytes) -> None:
        """Check for high-entropy sections that may indicate encryption or compression."""
        block_size = 4096
        high_entropy_blocks = 0
        total_blocks = len(data) // block_size

        for i in range(0, len(data) - block_size, block_size):
            block = data[i : i + block_size]
            byte_counts = [0] * 256
            for b in block:
                byte_counts[b] += 1

            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    prob = count / block_size
                    entropy -= prob * (prob and __import__("math").log2(prob))

            if entropy > 7.5:
                high_entropy_blocks += 1

        if total_blocks > 0:
            ratio = high_entropy_blocks / total_blocks
            self.result.raw_data["high_entropy_ratio"] = round(ratio, 3)

            if ratio > 0.7:
                self.add_finding(
                    title="Firmware appears mostly encrypted or compressed",
                    severity=Severity.INFO,
                    description=(
                        f"{ratio:.0%} of firmware blocks have high entropy (>7.5 bits/byte). "
                        "This may indicate full encryption which limits static analysis."
                    ),
                    remediation="Obtain decryption keys or analyze the device runtime for memory dumps.",
                )

    def _check_debug_artifacts(self, data: bytes) -> None:
        """Check for debug artifacts, build paths, and verbose error messages."""
        text = data.decode("latin-1", errors="ignore")

        debug_indicators = [
            (r"/home/\w+/", "Build path with username"),
            (r"DEBUG|VERBOSE|TRACE", "Debug logging enabled"),
            (r"gdbserver|gdb\.setup", "GDB debugger artifacts"),
            (r"JTAG|SWD|UART", "Debug interface references"),
            (r"telnetd", "Telnet daemon present"),
        ]

        for pattern, label in debug_indicators:
            if re.search(pattern, text):
                self.add_finding(
                    title=f"Debug artifact: {label}",
                    severity=Severity.MEDIUM if "telnet" in label.lower() else Severity.LOW,
                    description=f"Found {label} in firmware, which may expose sensitive debugging information or attack surface.",
                    remediation="Remove debug artifacts and disable unnecessary services in production firmware.",
                )

    def _check_elf_hardening(self, data: bytes) -> None:
        """Check ELF binaries for security hardening flags (NX, PIE, RELRO, stack canaries)."""
        # Find all ELF headers in the firmware
        elf_magic = b"\x7fELF"
        offset = 0
        elf_count = 0
        missing_hardening: dict[str, int] = {}

        while offset < len(data) - 64:
            pos = data.find(elf_magic, offset)
            if pos == -1:
                break

            elf_count += 1
            elf_data = data[pos:]

            if len(elf_data) < 64:
                offset = pos + 4
                continue

            # Parse ELF header basics
            ei_class = elf_data[4]  # 1=32-bit, 2=64-bit
            ei_data = elf_data[5]   # 1=little-endian, 2=big-endian
            endian = "<" if ei_data == 1 else ">"

            if ei_class == 1:  # 32-bit
                e_type = struct.unpack_from(f"{endian}H", elf_data, 16)[0]
                e_phoff = struct.unpack_from(f"{endian}I", elf_data, 28)[0]
                e_phentsize = struct.unpack_from(f"{endian}H", elf_data, 42)[0]
                e_phnum = struct.unpack_from(f"{endian}H", elf_data, 44)[0]
                ph_fmt = f"{endian}IIIIIIII"
                ph_size = 32
            elif ei_class == 2:  # 64-bit
                e_type = struct.unpack_from(f"{endian}H", elf_data, 16)[0]
                e_phoff = struct.unpack_from(f"{endian}Q", elf_data, 32)[0]
                e_phentsize = struct.unpack_from(f"{endian}H", elf_data, 54)[0]
                e_phnum = struct.unpack_from(f"{endian}H", elf_data, 56)[0]
                ph_fmt = f"{endian}IIQQQQQQ"
                ph_size = 56
            else:
                offset = pos + 4
                continue

            # Check if it's an executable or shared object
            if e_type not in (2, 3):  # ET_EXEC=2, ET_DYN=3
                offset = pos + 4
                continue

            # PIE check: executables should be ET_DYN (position-independent)
            if e_type == 2:
                missing_hardening["No PIE (position-independent executable)"] = (
                    missing_hardening.get("No PIE (position-independent executable)", 0) + 1
                )

            # Parse program headers to check NX and RELRO
            has_gnu_stack = False
            stack_executable = False
            has_gnu_relro = False

            if e_phoff > 0 and e_phnum < 100 and e_phoff + e_phnum * e_phentsize <= len(elf_data):
                for i in range(e_phnum):
                    ph_offset = e_phoff + i * e_phentsize
                    if ph_offset + ph_size > len(elf_data):
                        break

                    try:
                        ph = struct.unpack_from(ph_fmt, elf_data, ph_offset)
                    except struct.error:
                        break

                    p_type = ph[0]

                    # PT_GNU_STACK = 0x6474e551
                    if p_type == 0x6474E551:
                        has_gnu_stack = True
                        if ei_class == 1:
                            p_flags = ph[6]
                        else:
                            p_flags = ph[1]
                        # PF_X = 0x1
                        if p_flags & 0x1:
                            stack_executable = True

                    # PT_GNU_RELRO = 0x6474e552
                    if p_type == 0x6474E552:
                        has_gnu_relro = True

            if not has_gnu_stack or stack_executable:
                missing_hardening["No NX (executable stack)"] = (
                    missing_hardening.get("No NX (executable stack)", 0) + 1
                )

            if not has_gnu_relro:
                missing_hardening["No RELRO (relocation read-only)"] = (
                    missing_hardening.get("No RELRO (relocation read-only)", 0) + 1
                )

            # Check for stack canary symbols
            elf_text = elf_data[:min(len(elf_data), 65536)].decode("latin-1", errors="ignore")
            if "__stack_chk_fail" not in elf_text and "__stack_chk_guard" not in elf_text:
                missing_hardening["No stack canaries"] = (
                    missing_hardening.get("No stack canaries", 0) + 1
                )

            offset = pos + 4

        if elf_count == 0:
            return

        self.result.raw_data["elf_binaries_found"] = elf_count

        if missing_hardening:
            details = "; ".join(f"{issue}: {count} binary(ies)" for issue, count in missing_hardening.items())
            self.add_finding(
                title="ELF binaries missing security hardening",
                severity=Severity.HIGH,
                description=(
                    f"Analyzed {elf_count} ELF binary(ies). Missing hardening: {details}. "
                    "These omissions make exploitation of memory corruption vulnerabilities significantly easier."
                ),
                evidence=f"Hardening gaps: {missing_hardening}",
                remediation=(
                    "Compile with: -fstack-protector-strong (canaries), -Wl,-z,relro,-z,now (full RELRO), "
                    "-Wl,-z,noexecstack (NX), -fPIE -pie (PIE). Enable ASLR on the target OS."
                ),
            )

    def _check_crypto_issues(self, data: bytes) -> None:
        """Check for weak cryptographic implementations in firmware."""
        text = data.decode("latin-1", errors="ignore")

        crypto_issues = [
            (r"DES_ecb_encrypt|DES_set_key", "DES encryption (broken, 56-bit key)", Severity.HIGH),
            (r"MD5_Init|MD5_Update|MD5_Final|md5sum", "MD5 hash usage (collision-vulnerable)", Severity.MEDIUM),
            (r"SHA1_Init|SHA1_Update|sha1sum", "SHA-1 hash usage (collision-vulnerable)", Severity.MEDIUM),
            (r"RC4|arc4random_buf", "RC4 stream cipher (biased output)", Severity.HIGH),
            (r"rand\(\)|srand\(", "Weak PRNG (rand/srand instead of secure random)", Severity.HIGH),
            (r"ECB_MODE|ecb_encrypt|_ECB", "ECB block cipher mode (no diffusion)", Severity.HIGH),
        ]

        for pattern, label, severity in crypto_issues:
            if re.search(pattern, text):
                self.add_finding(
                    title=f"Weak cryptography: {label}",
                    severity=severity,
                    description=f"Found {label} in firmware. This cryptographic primitive is considered insecure.",
                    remediation="Use AES-256-GCM for encryption, SHA-256/SHA-3 for hashing, and OS-provided CSPRNG for random numbers.",
                )
