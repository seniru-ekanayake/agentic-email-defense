"""Self-Hosted DNS & Network Recon MCP Server (JSON-RPC over stdio).

Provides fast, zero-cost network intelligence:
- DNS A, AAAA, MX, TXT, PTR resolution via native socket / DoH
- SPF & DMARC policy record auditing
- DKIM selector record lookup
"""

from __future__ import annotations

import json
import socket
import sys
from typing import Any, Dict, List
import urllib.request
import urllib.parse


def resolve_doh_txt(domain: str) -> List[str]:
    """Retrieve TXT records using Cloudflare/Google public DoH."""
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=TXT"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": "MCP-DNS/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                answers = data.get("Answer", [])
                return [a.get("data", "").strip('"') for a in answers if "data" in a]
    except Exception:
        pass
    return []


def resolve_doh_mx(domain: str) -> List[str]:
    """Retrieve MX records using DoH."""
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=MX"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": "MCP-DNS/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                answers = data.get("Answer", [])
                return [a.get("data", "") for a in answers if "data" in a]
    except Exception:
        pass
    return []


def handle_dns_resolve(params: Dict[str, Any]) -> Dict[str, Any]:
    domain = params.get("domain", "").strip().lower()
    record_type = params.get("type", "A").upper()

    if not domain:
        return {"error": "Domain is required"}

    if record_type in ("A", "AAAA"):
        try:
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            addrinfo = socket.getaddrinfo(domain, None, family)
            ips = list(set([item[4][0] for item in addrinfo]))
            return {"domain": domain, "type": record_type, "records": ips, "status": "resolved"}
        except socket.gaierror:
            return {"domain": domain, "type": record_type, "records": [], "status": "nxdomain"}
    elif record_type == "TXT":
        txts = resolve_doh_txt(domain)
        return {"domain": domain, "type": "TXT", "records": txts, "status": "resolved" if txts else "no_records"}
    elif record_type == "MX":
        mxs = resolve_doh_mx(domain)
        return {"domain": domain, "type": "MX", "records": mxs, "status": "resolved" if mxs else "no_records"}

    return {"error": f"Unsupported record type: {record_type}"}


def handle_spf_dmarc_audit(params: Dict[str, Any]) -> Dict[str, Any]:
    domain = params.get("domain", "").strip().lower()
    if not domain:
        return {"error": "Domain is required"}

    # 1. Check SPF on domain
    domain_txts = resolve_doh_txt(domain)
    spf_record = next((t for t in domain_txts if t.lower().startswith("v=spf1")), None)

    # 2. Check DMARC on _dmarc.domain
    dmarc_txts = resolve_doh_txt(f"_dmarc.{domain}")
    dmarc_record = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)

    spf_policy = "none"
    if spf_record:
        if "-all" in spf_record:
            spf_policy = "hardfail"
        elif "~all" in spf_record:
            spf_policy = "softfail"
        elif "?all" in spf_record or "+all" in spf_record:
            spf_policy = "neutral_or_permissive"

    dmarc_policy = "none"
    if dmarc_record:
        if "p=reject" in dmarc_record.lower():
            dmarc_policy = "reject"
        elif "p=quarantine" in dmarc_record.lower():
            dmarc_policy = "quarantine"
        elif "p=none" in dmarc_record.lower():
            dmarc_policy = "none"

    return {
        "domain": domain,
        "has_spf": spf_record is not None,
        "spf_record": spf_record,
        "spf_policy": spf_policy,
        "has_dmarc": dmarc_record is not None,
        "dmarc_record": dmarc_record,
        "dmarc_policy": dmarc_policy,
        "is_spoofing_vulnerable": not (spf_record and dmarc_record and dmarc_policy in ("reject", "quarantine")),
    }


def handle_dkim_selector_check(params: Dict[str, Any]) -> Dict[str, Any]:
    domain = params.get("domain", "").strip().lower()
    selector = params.get("selector", "default").strip()

    if not domain:
        return {"error": "Domain is required"}

    dkim_domain = f"{selector}._domainkey.{domain}"
    txts = resolve_doh_txt(dkim_domain)
    dkim_record = next((t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()), None)

    return {
        "domain": domain,
        "selector": selector,
        "dkim_domain": dkim_domain,
        "has_dkim_key": dkim_record is not None,
        "dkim_record": dkim_record,
    }


TOOLS = {
    "dns_resolve": handle_dns_resolve,
    "spf_dmarc_audit": handle_spf_dmarc_audit,
    "dkim_selector_check": handle_dkim_selector_check,
}


def process_request(line: str) -> str:
    try:
        req = json.loads(line)
        method = req.get("method")
        msg_id = req.get("id")

        if method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "dns_resolve",
                            "description": "Resolve DNS A, AAAA, MX, or TXT records for a domain",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "domain": {"type": "string"},
                                    "type": {"type": "string", "enum": ["A", "AAAA", "MX", "TXT"]},
                                },
                                "required": ["domain"],
                            },
                        },
                        {
                            "name": "spf_dmarc_audit",
                            "description": "Audit SPF and DMARC enforcement records for spoofing vulnerability",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"domain": {"type": "string"}},
                                "required": ["domain"],
                            },
                        },
                        {
                            "name": "dkim_selector_check",
                            "description": "Lookup DKIM public key for a domain and selector",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "domain": {"type": "string"},
                                    "selector": {"type": "string"},
                                },
                                "required": ["domain", "selector"],
                            },
                        },
                    ]
                },
            })

        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name in TOOLS:
                handler = TOOLS[tool_name]
                result = handler(tool_args)
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                })
            else:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                })

        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request"},
        })
    except Exception as exc:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"},
        })


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        res = process_request(line)
        sys.stdout.write(res + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
