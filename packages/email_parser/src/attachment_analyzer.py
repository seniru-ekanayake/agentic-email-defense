"""
AttachmentAnalyzer: Production-Grade Static File & Archive Forensic Analysis Pipeline.
Safely inspects archives (.iso, .zip, .tar, .tgz), Office documents (.docx, .docm, .xlsx, .xlsm, .pptx),
PDF files (.pdf), and Windows binaries (.exe, .dll, .scr) without executing untrusted code on the host machine.
Supports safe recursive unpacking, macro/vbaProject.bin detection, embedded URL extraction,
and PDF /URI inspection with configurable safety limits.
"""

import io
import re
import time
import math
import struct
import hashlib
import zipfile
import tarfile
import logging
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger("AttachmentAnalyzer")


class ContainedFile(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None
    nesting_depth: int = 1


class SectionAnalysis(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    is_packed: bool = False


class PeInspectionResult(BaseModel):
    machine: str
    architecture: str
    compile_timestamp: int
    subsystem: str
    entry_point_rva: str
    number_of_sections: int
    sections: List[SectionAnalysis] = Field(default_factory=list)
    suspicious_apis: List[str] = Field(default_factory=list)
    has_high_entropy_sections: bool = False
    is_likely_packed: bool = False


class DocumentInspectionResult(BaseModel):
    has_macros: bool = False
    vba_project_present: bool = False
    ole_objects_present: bool = False
    embedded_urls: List[str] = Field(default_factory=list)
    pdf_uri_actions: List[str] = Field(default_factory=list)
    pdf_goto_actions: List[str] = Field(default_factory=list)


class AttachmentAnalysisReport(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    md5: str
    mime_type: str
    magic_description: str
    container_type: str  # ZIP, TAR, ISO, PE_BINARY, DOCUMENT, UNKNOWN
    contained_files: List[ContainedFile] = Field(default_factory=list)
    pe_analysis: Optional[PeInspectionResult] = None
    document_analysis: Optional[DocumentInspectionResult] = None
    motw_evasion_detected: bool = False
    nested_extension_detected: bool = False
    zip_bomb_detected: bool = False
    limit_exceeded: bool = False
    limit_exceeded_reason: Optional[str] = None
    risk_score: float = 0.0
    risk_factors: List[str] = Field(default_factory=list)
    analysis_mode: str = "STATIC_ANALYSIS"
    detonation_status: str = "NOT_CONFIGURED"
    detonation_message: str = "Dynamic binary detonation sandbox not configured in host environment; static forensic analysis completed."

    @property
    def embedded_urls(self) -> List[str]:
        if self.document_analysis:
            return self.document_analysis.embedded_urls
        return []


class AttachmentAnalyzer:
    """
    Safely inspects file attachments in memory.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".ps1xml", ".msc", ".hta", ".cpl", ".iso", ".img",
        ".vhd", ".vhdx", ".lnk", ".pif", ".docm", ".xlsm", ".pptm"
    }

    SUSPICIOUS_PE_APIS = [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "QueueUserAPC",
        "NtQueueApcThread", "SetWindowsHookExA", "SetWindowsHookExW", "InternetOpenA",
        "InternetOpenUrlA", "URLDownloadToFileA", "URLDownloadToFileW", "WinExec",
        "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
        "RegSetValueExA", "AdjustTokenPrivileges", "CryptEncrypt", "CryptDecrypt"
    ]

    def __init__(
        self,
        max_recursion_depth: int = 3,
        max_file_size_bytes: int = 50 * 1024 * 1024,
        max_archive_entries: int = 1000,
        max_decompression_ratio: float = 100.0,
        max_processing_time_sec: float = 5.0
    ):
        self.max_recursion_depth = max_recursion_depth
        self.max_file_size_bytes = max_file_size_bytes
        self.max_archive_entries = max_archive_entries
        self.max_decompression_ratio = max_decompression_ratio
        self.max_processing_time_sec = max_processing_time_sec

    def analyze_bytes(
        self,
        filename: str,
        payload: bytes,
        declared_mime: str = "application/octet-stream",
        current_depth: int = 1,
        start_time: Optional[float] = None
    ) -> AttachmentAnalysisReport:
        t0 = start_time or time.time()
        size = len(payload)
        sha256 = hashlib.sha256(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()

        # Enforce file size limit
        if size > self.max_file_size_bytes:
            return AttachmentAnalysisReport(
                filename=filename,
                size_bytes=size,
                sha256=sha256,
                md5=md5,
                mime_type=declared_mime,
                magic_description="Oversized File",
                container_type="UNKNOWN",
                limit_exceeded=True,
                limit_exceeded_reason=f"File size ({size} bytes) exceeds safety limit ({self.max_file_size_bytes} bytes)",
                risk_score=20.0,
                risk_factors=[f"File size exceeds safety threshold ({size} bytes)"]
            )

        # Identify magic bytes
        magic = "Unknown / Binary"
        container_type = "UNKNOWN"

        if payload.startswith(b"MZ"):
            magic = "Windows Executable / Dynamic Link Library (PE)"
            container_type = "PE_BINARY"
        elif payload.startswith(b"PK\x03\x04"):
            magic = "Zip Archive / Compressed Container / OpenXML Document"
            container_type = "ZIP"
        elif payload.startswith(b"\x1f\x8b"):
            magic = "Gzip Compressed Archive"
            container_type = "TAR"
        elif self._is_tar_file(payload):
            magic = "POSIX Tar Archive"
            container_type = "TAR"
        elif self._is_iso_image(payload):
            magic = "ISO 9660 Optical Disc Image (MOTW Container)"
            container_type = "ISO"
        elif payload.startswith(b"%PDF"):
            magic = "Adobe Portable Document Format (PDF)"
            container_type = "DOCUMENT"
        elif payload.startswith(b"\xD0\xCF\x11\xE0"):
            magic = "Microsoft Compound File Binary / OLE Object"
            container_type = "DOCUMENT"

        report = AttachmentAnalysisReport(
            filename=filename,
            size_bytes=size,
            sha256=sha256,
            md5=md5,
            mime_type=declared_mime,
            magic_description=magic,
            container_type=container_type
        )

        # Check timeout limit
        if time.time() - t0 > self.max_processing_time_sec:
            report.limit_exceeded = True
            report.limit_exceeded_reason = f"Processing time exceeded ({self.max_processing_time_sec}s safety limit)"
            report.risk_factors.append(report.limit_exceeded_reason)
            return report

        # Double extension check
        lower_fn = filename.lower()
        parts = lower_fn.split(".")
        if len(parts) > 2 and f".{parts[-1]}" in self.SUSPICIOUS_EXTENSIONS:
            report.nested_extension_detected = True
            report.risk_factors.append(f"Deceptive nested extension detected: '{filename}' (spoofing .{parts[-2]})")
            report.risk_score += 40.0

        # Run specialized container inspection
        if container_type == "ZIP":
            self._inspect_zip(payload, report, current_depth, t0)
        elif container_type == "TAR":
            self._inspect_tar(payload, report, current_depth, t0)
        elif container_type == "ISO":
            self._inspect_iso(payload, report)
        elif container_type == "PE_BINARY":
            self._inspect_pe(payload, report)
        elif container_type == "DOCUMENT":
            self._inspect_document(payload, report)

        # Normalize score
        report.risk_score = min(100.0, max(0.0, report.risk_score))
        return report

    def _is_tar_file(self, payload: bytes) -> bool:
        if len(payload) >= 512:
            magic = payload[257:262]
            return magic in (b"ustar", b"ustar\x00")
        return False

    def _is_iso_image(self, payload: bytes) -> bool:
        if len(payload) > 0x8006:
            if payload[0x8000:0x8006] in (b"\x01CD001", b"\x02CD001"):
                return True
        return False

    def _inspect_zip(self, payload: bytes, report: AttachmentAnalysisReport, depth: int, start_time: float):
        try:
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                infolist = zf.infolist()

                if len(infolist) > self.max_archive_entries:
                    report.limit_exceeded = True
                    report.limit_exceeded_reason = f"Archive entries count ({len(infolist)}) exceeds limit ({self.max_archive_entries})"
                    report.risk_factors.append(report.limit_exceeded_reason)

                # Check for OpenXML macros (vbaProject.bin)
                names = [info.filename for info in infolist]
                has_vba = any("vbaProject.bin" in n or "word/vba" in n.lower() or "xl/vba" in n.lower() for n in names)
                
                # Extract embedded URLs from XML documents
                embedded_urls = []
                for n in names:
                    if n.endswith(".xml") or n.endswith(".rels"):
                        try:
                            content = zf.read(n).decode("utf-8", errors="ignore")
                            urls_found = re.findall(r"https?://[^\s<>\"']+", content)
                            urls_found += re.findall(r"file://[^\s<>\"']+", content)
                            urls_found += re.findall(r"search-ms:[^\s<>\"']+", content)
                            for u in urls_found:
                                if u not in embedded_urls:
                                    embedded_urls.append(u)
                        except Exception:
                            pass

                if has_vba or any(report.filename.lower().endswith(ext) for ext in [".docm", ".xlsm", ".pptm"]):
                    doc_res = DocumentInspectionResult(
                        has_macros=True,
                        vba_project_present=has_vba,
                        embedded_urls=embedded_urls
                    )
                    report.document_analysis = doc_res
                    report.risk_factors.append(f"Macro-enabled document container ('{report.filename}', vbaProject.bin present)")
                    report.risk_score += 45.0

                    if embedded_urls:
                        report.risk_factors.append(f"Embedded URLs found in document XML: {embedded_urls[0]}")
                        report.risk_score += 15.0

                total_uncompressed = 0
                for info in infolist:
                    if time.time() - start_time > self.max_processing_time_sec:
                        report.limit_exceeded = True
                        report.limit_exceeded_reason = "Archive unpacking processing timeout"
                        break

                    total_uncompressed += info.file_size
                    member_bytes = zf.read(info.filename)
                    member_hash = hashlib.sha256(member_bytes).hexdigest()
                    
                    is_suspicious = False
                    reason = None
                    m_lower = info.filename.lower()
                    for ext in self.SUSPICIOUS_EXTENSIONS:
                        if m_lower.endswith(ext):
                            is_suspicious = True
                            reason = f"Archive contains high-risk payload: {info.filename}"
                            break

                    report.contained_files.append(ContainedFile(
                        filename=info.filename,
                        size_bytes=info.file_size,
                        sha256=member_hash,
                        is_suspicious=is_suspicious,
                        suspicious_reason=reason,
                        nesting_depth=depth
                    ))

                    if is_suspicious:
                        report.risk_factors.append(reason)
                        report.risk_score += 45.0

                    # Safe Recursive Unpacking up to max_recursion_depth
                    if depth < self.max_recursion_depth and (member_bytes.startswith(b"PK\x03\x04") or member_bytes.startswith(b"MZ")):
                        child_report = self.analyze_bytes(
                            filename=info.filename,
                            payload=member_bytes,
                            current_depth=depth + 1,
                            start_time=start_time
                        )
                        for c_file in child_report.contained_files:
                            report.contained_files.append(c_file)
                        for c_risk in child_report.risk_factors:
                            if c_risk not in report.risk_factors:
                                report.risk_factors.append(f"Nested level {depth+1}: {c_risk}")
                        report.risk_score += child_report.risk_score * 0.5

                # Zip bomb ratio check
                if len(payload) > 0:
                    ratio = total_uncompressed / len(payload)
                    if ratio > self.max_decompression_ratio:
                        report.zip_bomb_detected = True
                        report.risk_factors.append(f"Excessive compression ratio ({ratio:.1f}x) - potential decompression bomb")
                        report.risk_score += 50.0

        except Exception as e:
            logger.warning(f"Failed to unpack ZIP archive: {e}")
            report.risk_factors.append(f"Malformed or encrypted ZIP archive: {str(e)}")

    def _inspect_tar(self, payload: bytes, report: AttachmentAnalysisReport, depth: int, start_time: float):
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tf:
                members = tf.getmembers()
                if len(members) > self.max_archive_entries:
                    report.limit_exceeded = True
                    report.limit_exceeded_reason = f"Tar members count ({len(members)}) exceeds limit ({self.max_archive_entries})"
                    report.risk_factors.append(report.limit_exceeded_reason)

                for member in members:
                    if time.time() - start_time > self.max_processing_time_sec:
                        report.limit_exceeded = True
                        report.limit_exceeded_reason = "Tar unpacking timeout"
                        break

                    if member.isfile():
                        f = tf.extractfile(member)
                        member_bytes = f.read() if f else b""
                        member_hash = hashlib.sha256(member_bytes).hexdigest()

                        is_suspicious = False
                        reason = None
                        m_lower = member.name.lower()
                        for ext in self.SUSPICIOUS_EXTENSIONS:
                            if m_lower.endswith(ext):
                                is_suspicious = True
                                reason = f"Tar archive contains executable: {member.name}"
                                break

                        report.contained_files.append(ContainedFile(
                            filename=member.name,
                            size_bytes=member.size,
                            sha256=member_hash,
                            is_suspicious=is_suspicious,
                            suspicious_reason=reason,
                            nesting_depth=depth
                        ))

                        if is_suspicious:
                            report.risk_factors.append(reason)
                            report.risk_score += 40.0

                        # Safe Recursive Unpacking
                        if depth < self.max_recursion_depth and (member_bytes.startswith(b"PK\x03\x04") or member_bytes.startswith(b"MZ")):
                            child_report = self.analyze_bytes(
                                filename=member.name,
                                payload=member_bytes,
                                current_depth=depth + 1,
                                start_time=start_time
                            )
                            for c_file in child_report.contained_files:
                                report.contained_files.append(c_file)
                            for c_risk in child_report.risk_factors:
                                if c_risk not in report.risk_factors:
                                    report.risk_factors.append(f"Nested level {depth+1}: {c_risk}")
                            report.risk_score += child_report.risk_score * 0.5
        except Exception as e:
            logger.warning(f"Failed to inspect TAR archive: {e}")

    def _inspect_iso(self, payload: bytes, report: AttachmentAnalysisReport):
        report.motw_evasion_detected = True
        report.risk_factors.append("ISO/IMG container delivery detected: Common technique to evade Windows Mark-of-the-Web (MOTW)")
        report.risk_score += 35.0

        found_members = set()
        for ext in self.SUSPICIOUS_EXTENSIONS:
            b_ext = ext.encode()
            pos = 0
            while True:
                idx = payload.find(b_ext, pos)
                if idx == -1:
                    break
                name_chars = []
                for b in reversed(payload[max(0, idx - 50):idx]):
                    if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b in (45, 95, 46):
                        name_chars.append(chr(b))
                    else:
                        break
                if name_chars:
                    clean_name = "".join(reversed(name_chars)) + ext
                    if len(clean_name) > len(ext):
                        found_members.add(clean_name)
                pos = idx + len(b_ext)

        for fn in sorted(found_members):
            reason = f"ISO contains executable/script payload: {fn} (Mark-of-the-Web bypass)"
            report.contained_files.append(ContainedFile(
                filename=fn,
                size_bytes=0,
                sha256=hashlib.sha256(fn.encode()).hexdigest(),
                is_suspicious=True,
                suspicious_reason=reason
            ))
            report.risk_factors.append(reason)
            report.risk_score += 40.0

    def _inspect_pe(self, payload: bytes, report: AttachmentAnalysisReport):
        try:
            if len(payload) < 64:
                return

            e_lfanew = struct.unpack_from("<I", payload, 0x3C)[0]
            if e_lfanew + 24 > len(payload):
                return

            pe_sig = payload[e_lfanew:e_lfanew+4]
            if pe_sig != b"PE\x00\x00":
                return

            coff_offset = e_lfanew + 4
            machine_val, num_sections, timestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
                "<HHIIIHH", payload, coff_offset
            )

            machine_map = {
                0x014c: "i386 (32-bit x86)",
                0x8664: "AMD64 (64-bit x64)",
                0xAA64: "ARM64",
                0x0200: "IA64"
            }
            machine_str = machine_map.get(machine_val, f"Unknown (0x{machine_val:04X})")

            opt_offset = coff_offset + 20
            magic_opt = struct.unpack_from("<H", payload, opt_offset)[0]
            is_64bit = magic_opt == 0x20b
            arch_str = "PE32+ (64-bit)" if is_64bit else "PE32 (32-bit)"

            entry_rva = struct.unpack_from("<I", payload, opt_offset + 16)[0]
            subsystem_offset = opt_offset + (68 if is_64bit else 68)
            subsys_val = struct.unpack_from("<H", payload, subsystem_offset)[0]
            subsys_map = {1: "Native", 2: "Windows GUI", 3: "Windows CUI / Console", 7: "POSIX"}
            subsys_str = subsys_map.get(subsys_val, f"Subsystem {subsys_val}")

            section_hdr_offset = opt_offset + opt_hdr_size
            sections_list: List[SectionAnalysis] = []
            has_packed = False

            for i in range(num_sections):
                s_off = section_hdr_offset + (i * 40)
                if s_off + 40 > len(payload):
                    break
                raw_name = payload[s_off:s_off+8].split(b"\x00")[0].decode(errors="ignore")
                v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", payload, s_off + 8)
                
                sec_bytes = payload[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(payload) else b""
                entropy = self._shannon_entropy(sec_bytes) if sec_bytes else 0.0
                is_packed_sec = entropy >= 7.2

                if is_packed_sec:
                    has_packed = True

                sections_list.append(SectionAnalysis(
                    name=raw_name,
                    virtual_size=v_size,
                    raw_size=raw_size,
                    entropy=round(entropy, 2),
                    is_packed=is_packed_sec
                ))

            suspicious_apis_found = []
            for api in self.SUSPICIOUS_PE_APIS:
                if api.encode("ascii") in payload:
                    suspicious_apis_found.append(api)

            pe_result = PeInspectionResult(
                machine=machine_str,
                architecture=arch_str,
                compile_timestamp=timestamp,
                subsystem=subsys_str,
                entry_point_rva=f"0x{entry_rva:08X}",
                number_of_sections=num_sections,
                sections=sections_list,
                suspicious_apis=suspicious_apis_found,
                has_high_entropy_sections=has_packed,
                is_likely_packed=has_packed
            )
            report.pe_analysis = pe_result

            report.risk_factors.append(f"Executable binary payload ({arch_str}, {machine_str})")
            report.risk_score += 45.0

            if has_packed:
                report.risk_factors.append("Packed/Obfuscated sections detected (Shannon entropy >= 7.2)")
                report.risk_score += 25.0

            if suspicious_apis_found:
                report.risk_factors.append(f"Suspicious API imports detected: {', '.join(suspicious_apis_found[:4])}")
                report.risk_score += 20.0

        except Exception as e:
            logger.warning(f"PE header analysis encountered error: {e}")
            report.risk_factors.append(f"PE structure parsing error: {str(e)}")

    def _inspect_document(self, payload: bytes, report: AttachmentAnalysisReport):
        """
        Inspects PDF and OLE Compound Documents for embedded URLs, /URI actions, /GoTo actions, and OLE streams.
        """
        pdf_uris = []
        pdf_gotos = []
        ole_present = payload.startswith(b"\xD0\xCF\x11\xE0")
        has_vba = b"vbaProject.bin" in payload or b"VBA" in payload or b"AutoOpen" in payload

        if payload.startswith(b"%PDF"):
            # Extract PDF /URI and /GoTo actions
            str_content = payload.decode("latin-1", errors="ignore")
            uri_matches = re.findall(r"/URI\s*\(([^)]+)\)", str_content)
            uri_matches += re.findall(r"/URI\s*<([^>]+)>", str_content)
            for u in uri_matches:
                if u not in pdf_uris:
                    pdf_uris.append(u)

            goto_matches = re.findall(r"/GoTo\s*[\/<]([^>\s]+)", str_content)
            for g in goto_matches:
                if g not in pdf_gotos:
                    pdf_gotos.append(g)

            # Check for embedded JS in PDF
            if "/JavaScript" in str_content or "/JS" in str_content:
                report.risk_factors.append("PDF document contains embedded JavaScript (/JS /JavaScript action)")
                report.risk_score += 30.0

            if pdf_uris:
                report.risk_factors.append(f"PDF document contains embedded /URI action: {pdf_uris[0]}")
                report.risk_score += 25.0

        doc_res = DocumentInspectionResult(
            has_macros=has_vba,
            vba_project_present=has_vba,
            ole_objects_present=ole_present,
            embedded_urls=pdf_uris,
            pdf_uri_actions=pdf_uris,
            pdf_goto_actions=pdf_gotos
        )
        report.document_analysis = doc_res

        if ole_present:
            report.risk_factors.append("OLE Compound File object embedded in attachment")
            report.risk_score += 20.0

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
