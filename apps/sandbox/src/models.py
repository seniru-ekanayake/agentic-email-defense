"""
Data Models and Telemetry Schemas for the Isolated Behavioral Analysis Sandbox.
Includes Email Rendering Sandbox and Dedicated URL / Link Detonation Models.
"""

from typing import List, Dict, Any, Optional
import datetime
from pydantic import BaseModel, Field


class NetworkEvent(BaseModel):
    url: str
    method: str = "GET"
    resource_type: str = "document"  # document, stylesheet, image, script, xhr, fetch, other
    headers: Dict[str, str] = Field(default_factory=dict)
    status_code: Optional[int] = None
    is_blocked: bool = False
    blocked_reason: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DomMutationEvent(BaseModel):
    mutation_type: str  # childList, attributes, characterData, forcedUriExecution
    target_tag: str
    attribute_changed: Optional[str] = None
    value: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class JsConsoleEvent(BaseModel):
    level: str  # info, warning, error
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class BrowserStorageEvent(BaseModel):
    storage_type: str  # cookie, localStorage, sessionStorage
    key: str
    action: str  # read, write, delete
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class SandboxTelemetry(BaseModel):
    execution_id: str
    email_message_id: str
    execution_duration_ms: float
    network_requests: List[NetworkEvent] = Field(default_factory=list)
    dns_queries: List[str] = Field(default_factory=list)
    redirect_chains: List[List[str]] = Field(default_factory=list)
    dom_mutations: List[DomMutationEvent] = Field(default_factory=list)
    js_events: List[JsConsoleEvent] = Field(default_factory=list)
    storage_events: List[BrowserStorageEvent] = Field(default_factory=list)
    blocked_destinations: List[str] = Field(default_factory=list)
    rendering_anomalies: List[str] = Field(default_factory=list)
    ssrf_attempts: List[str] = Field(default_factory=list)
    forced_callout_destinations: List[str] = Field(default_factory=list)
    is_benign: bool = True
    summary: str = "No anomalous behavior observed during rendering."


class UrlPageFeatures(BaseModel):
    title: Optional[str] = None
    has_login_form: bool = False
    has_password_field: bool = False
    impersonated_brand: Optional[str] = None  # e.g. "Microsoft 365", "Google Workspace", "Okta", "PayPal"
    external_scripts: List[str] = Field(default_factory=list)
    iframe_sources: List[str] = Field(default_factory=list)
    obfuscated_javascript: bool = False


class UrlSandboxReport(BaseModel):
    scan_id: str
    submitted_url: str
    final_destination_url: str
    redirect_chain: List[str] = Field(default_factory=list)
    is_ip_based: bool = False
    is_punycode_homograph: bool = False
    is_shortener: bool = False
    network_guard_blocked: bool = False
    blocked_reason: Optional[str] = None
    page_features: UrlPageFeatures = Field(default_factory=UrlPageFeatures)
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "CLEAN", "BLOCKED_SSRF"
    threat_category: Optional[str] = None  # "CREDENTIAL_PHISHING", "BROWSER_EXPLOIT", "SSRF_PROBE", "DECEPTIVE_REDIRECT"
    risk_score: float = Field(ge=0.0, le=100.0)
    evidence: List[str] = Field(default_factory=list)
    scanned_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
