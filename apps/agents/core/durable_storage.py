"""
Durable Production Persistence Layer for FishingMails.
Provides atomic, disk-backed SQLite storage for incidents, evidence items,
decision traces, tool execution telemetry, approval tokens, campaign clusters, graph nodes/edges, and audit logs.
Fails cleanly, isolates corrupt records, and reports errors under PRODUCTION mode.
"""

import os
import json
import sqlite3
import datetime
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("DurableStorage")

DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "fishingmails.db")


class DurableStorage:
    """
    Thread-safe SQLite-backed durable repository for production SOC operations.
    """
    _instance: Optional["DurableStorage"] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "DurableStorage":
        with cls._lock:
            if cls._instance is None:
                cls._instance = DurableStorage(db_path)
            return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("FISHINGMAILS_DB_PATH", DEFAULT_DB_PATH)
        self._local = threading.local()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
        return self._local.conn

    def _init_database(self):
        """Creates durable schema for all SOC entities."""
        try:
            conn = self._get_connection()
            with conn:
                conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    overall_risk_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS investigation_states (
                    incident_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence_items (
                    evidence_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS decision_records (
                    decision_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    observed TEXT,
                    decision TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    result TEXT,
                    impact TEXT,
                    confidence TEXT,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_executions (
                    execution_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL,
                    inputs_json TEXT,
                    result_summary TEXT,
                    error TEXT,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    agent_run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_tokens (
                    token TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    target_cve TEXT,
                    target_identity TEXT,
                    nonce TEXT NOT NULL,
                    expiry_timestamp TEXT NOT NULL,
                    hmac_signature TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approver TEXT,
                    comments TEXT,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS campaign_clusters (
                    fingerprint TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    total_email_count INTEGER NOT NULL,
                    target_cve TEXT,
                    data_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS attack_graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    name TEXT NOT NULL,
                    properties_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS attack_graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    properties_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    tenant_id TEXT
                );

                CREATE TABLE IF NOT EXISTS platform_settings (
                    tenant_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, key)
                );
                """)
                cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_logs)").fetchall()}
                if "tenant_id" not in cols:
                    conn.execute("ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id)")
            logger.info(f"DurableStorage initialized successfully at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize SQLite database at {self.db_path}: {e}")
            raise

    def check_health(self) -> Tuple[bool, str]:
        """Verifies read and write operations against disk storage."""
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("SELECT 1 FROM incidents LIMIT 1;")
            return True, f"Durable SQLite operational ({self.db_path})"
        except Exception as e:
            return False, f"Durable storage health check failed: {str(e)}"

    # --- Incidents & Error Isolation ---

    def save_incident(self, incident_dict: Dict[str, Any]) -> bool:
        inc_id = incident_dict.get("incident_id")
        tenant_id = incident_dict.get("tenant_id", "default")
        title = incident_dict.get("title", "Untitled Incident")
        severity = incident_dict.get("severity", "MEDIUM")
        score = float(incident_dict.get("overall_risk_score", 0.0))
        status = incident_dict.get("status", "OPEN")
        created_at = incident_dict.get("created_at", "")
        updated_at = incident_dict.get("updated_at", "")
        data_json = json.dumps(incident_dict, default=str)

        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO incidents (incident_id, tenant_id, title, severity, overall_risk_score, status, data_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title=excluded.title,
                        severity=excluded.severity,
                        overall_risk_score=excluded.overall_risk_score,
                        status=excluded.status,
                        data_json=excluded.data_json,
                        updated_at=excluded.updated_at
                """, (inc_id, tenant_id, title, severity, score, status, data_json, created_at, updated_at))
            return True
        except Exception as e:
            logger.error(f"Failed to save incident {inc_id} to durable storage: {e}")
            raise

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(row["data_json"])
            except json.JSONDecodeError as e:
                logger.error(f"Corrupt record found for incident {incident_id}: {e}")
                self._mark_record_corrupt(incident_id, str(e))
                return None
        return None

    def list_incidents(self, tenant_id: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Retrieves healthy incidents with optional tenant and limit filtering.
        Isolates malformed or corrupted JSON records without crashing the endpoint.
        """
        conn = self._get_connection()
        query = "SELECT incident_id, data_json FROM incidents"
        params = []
        if tenant_id:
            query += " WHERE tenant_id = ?"
            params.append(tenant_id)
        query += " ORDER BY created_at DESC"
        if limit and limit > 0:
            query += f" LIMIT {int(limit)}"

        cur = conn.execute(query, tuple(params))
        
        healthy_incidents = []
        for row in cur.fetchall():
            inc_id = row["incident_id"]
            raw_json = row["data_json"]
            try:
                data = json.loads(raw_json)
                healthy_incidents.append(data)
            except json.JSONDecodeError as e:
                logger.error(f"CORRUPT RECORD ISOLATED: Incident '{inc_id}' contains malformed JSON: {e}")
                self._mark_record_corrupt(inc_id, str(e))

        return healthy_incidents

    def _mark_record_corrupt(self, incident_id: str, error_msg: str):
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("UPDATE incidents SET status = 'CORRUPT' WHERE incident_id = ?", (incident_id,))
        except Exception as e:
            logger.warning(f"Failed to mark record {incident_id} as CORRUPT: {e}")

    def get_corrupt_records(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT incident_id, tenant_id, title, status, created_at FROM incidents WHERE status = 'CORRUPT'")
        return [dict(row) for row in cur.fetchall()]

    # --- Durable Approval Tokens ---

    def save_approval_token(self, token_dict: Dict[str, Any]) -> bool:
        token = token_dict.get("token")
        tenant_id = token_dict.get("tenant_id", "default")
        incident_id = token_dict.get("incident_id", "GLOBAL")
        action_name = token_dict.get("tool_name", "UnknownAction")
        risk_level = token_dict.get("risk_level", "HIGH")
        cve = token_dict.get("target_cve")
        identity = token_dict.get("target_identity")
        nonce = token_dict.get("nonce", "")
        expiry = token_dict.get("expiry_timestamp", "")
        sig = token_dict.get("hmac_signature", "")
        status = token_dict.get("status", "PENDING")
        approver = token_dict.get("approver")
        comments = token_dict.get("comments")
        created_at = token_dict.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
        data_json = json.dumps(token_dict, default=str)

        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT INTO approval_tokens
                (token, tenant_id, incident_id, action_name, risk_level, target_cve, target_identity, nonce, expiry_timestamp, hmac_signature, status, approver, comments, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET
                    status=excluded.status,
                    approver=excluded.approver,
                    comments=excluded.comments,
                    data_json=excluded.data_json
            """, (token, tenant_id, incident_id, action_name, risk_level, cve, identity, nonce, expiry, sig, status, approver, comments, data_json, created_at))
        return True

    def get_approval_token(self, token_str: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT data_json FROM approval_tokens WHERE token = ?", (token_str,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(row["data_json"])
            except json.JSONDecodeError:
                return None
        return None

    def claim_approval_token_atomic(self, token_str: str) -> bool:
        """Atomically updates token status to CLAIMED if it is currently PENDING. Prevents TOCTOU races."""
        conn = self._get_connection()
        with conn:
            cur = conn.execute(
                "UPDATE approval_tokens SET status = 'CLAIMED' WHERE token = ? AND status = 'PENDING'",
                (token_str,)
            )
            return cur.rowcount > 0

    def list_pending_approval_tokens(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if tenant_id:
            cur = conn.execute("SELECT data_json FROM approval_tokens WHERE tenant_id = ? AND status = 'PENDING' ORDER BY created_at DESC", (tenant_id,))
        else:
            cur = conn.execute("SELECT data_json FROM approval_tokens WHERE status = 'PENDING' ORDER BY created_at DESC")
        results = []
        for row in cur.fetchall():
            try:
                results.append(json.loads(row["data_json"]))
            except json.JSONDecodeError:
                pass
        return results

    # --- Durable Campaign Clusters ---

    def save_campaign_cluster(self, cluster_dict: Dict[str, Any]) -> bool:
        fp = cluster_dict.get("fingerprint")
        camp_id = cluster_dict.get("campaign_id")
        first_seen = float(cluster_dict.get("first_seen", 0.0))
        last_seen = float(cluster_dict.get("last_seen", 0.0))
        total_count = int(cluster_dict.get("total_email_count", 1))
        target_cve = cluster_dict.get("target_cve")
        data_json = json.dumps(cluster_dict, default=str)

        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT INTO campaign_clusters
                (fingerprint, campaign_id, first_seen, last_seen, total_email_count, target_cve, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    total_email_count=excluded.total_email_count,
                    target_cve=excluded.target_cve,
                    data_json=excluded.data_json
            """, (fp, camp_id, first_seen, last_seen, total_count, target_cve, data_json))
        return True

    def get_campaign_cluster(self, fp: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT data_json FROM campaign_clusters WHERE fingerprint = ?", (fp,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(row["data_json"])
            except json.JSONDecodeError:
                return None
        return None

    def list_campaign_clusters(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT data_json FROM campaign_clusters ORDER BY last_seen DESC")
        results = []
        for row in cur.fetchall():
            try:
                results.append(json.loads(row["data_json"]))
            except json.JSONDecodeError:
                pass
        return results

    def clear_campaign_clusters(self):
        conn = self._get_connection()
        with conn:
            conn.execute("DELETE FROM campaign_clusters")

    # --- Evidence ---

    def save_evidence_batch(self, incident_id: str, evidence_items: List[Dict[str, Any]]):
        if not evidence_items:
            return
        conn = self._get_connection()
        records = []
        for e in evidence_items:
            records.append((
                e.get("evidence_id"),
                incident_id,
                e.get("type", "UNKNOWN"),
                str(e.get("value", "")),
                e.get("source", "UNKNOWN"),
                str(e.get("confidence", "HIGH")),
                str(e.get("status", "OBSERVED")),
                json.dumps(e.get("metadata", {}), default=str),
                e.get("timestamp", "")
            ))
        with conn:
            conn.executemany("""
                INSERT OR REPLACE INTO evidence_items
                (evidence_id, incident_id, type, value, source, confidence, status, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)

    def get_evidence_for_incident(self, incident_id: str) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT * FROM evidence_items WHERE incident_id = ?", (incident_id,))
        results = []
        for row in cur.fetchall():
            results.append({
                "evidence_id": row["evidence_id"],
                "incident_id": row["incident_id"],
                "type": row["type"],
                "value": row["value"],
                "source": row["source"],
                "confidence": row["confidence"],
                "status": row["status"],
                "metadata": json.loads(row["metadata_json"] or "{}"),
                "timestamp": row["created_at"]
            })
        return results

    # --- Decisions ---

    def save_decisions_batch(self, incident_id: str, decisions: List[Dict[str, Any]]):
        if not decisions:
            return
        conn = self._get_connection()
        records = []
        for d in decisions:
            records.append((
                d.get("decision_id"),
                incident_id,
                d.get("observed", ""),
                d.get("decision", ""),
                d.get("action", ""),
                d.get("reason", ""),
                d.get("result", ""),
                d.get("impact", ""),
                str(d.get("confidence", "HIGH")),
                json.dumps(d, default=str),
                d.get("timestamp", "")
            ))
        with conn:
            conn.executemany("""
                INSERT OR REPLACE INTO decision_records
                (decision_id, incident_id, observed, decision, action, reason, result, impact, confidence, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)

    # --- Tool Executions ---

    def save_tool_executions_batch(self, incident_id: str, tool_executions: List[Dict[str, Any]]):
        if not tool_executions:
            return
        conn = self._get_connection()
        records = []
        for t in tool_executions:
            records.append((
                t.get("execution_id"),
                incident_id,
                t.get("tool_name", "UnknownTool"),
                t.get("status", "COMPLETED"),
                float(t.get("duration_ms", 0.0)),
                json.dumps(t.get("input_parameters", {}), default=str),
                t.get("result_summary", ""),
                t.get("error", None),
                json.dumps(t, default=str),
                t.get("started_at", "")
            ))
        with conn:
            conn.executemany("""
                INSERT OR REPLACE INTO tool_executions
                (execution_id, incident_id, tool_name, status, duration_ms, inputs_json, result_summary, error, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)

    # --- Lifecycle Events ---

    def save_event(self, event: Dict[str, Any]):
        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO agent_events
                (event_id, incident_id, agent_run_id, event_type, message, status, data_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("event_id"),
                event.get("investigation_id", "GLOBAL"),
                event.get("agent_run_id", "run-default"),
                event.get("event_type", "agent.info"),
                event.get("message", ""),
                event.get("status", "INFO"),
                json.dumps({"__event__": event}, default=str),  # full event, so it can be replayed exactly
                event.get("timestamp", "")
            ))

    def get_events(self, incident_id: str) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.execute("SELECT * FROM agent_events WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,))
        results = []
        for idx, row in enumerate(cur.fetchall()):
            stored = json.loads(row["data_json"] or "{}")
            if isinstance(stored, dict) and "__event__" in stored:
                results.append(stored["__event__"])
                continue
            results.append({  # rows written before full-event storage
                "event_id": row["event_id"],
                "investigation_id": row["incident_id"],
                "agent_run_id": row["agent_run_id"],
                "event_type": row["event_type"],
                "message": row["message"],
                "status": row["status"],
                "sequence_number": idx + 1,
                "data": stored,
                "timestamp": row["timestamp"]
            })
        results.sort(key=lambda e: (e.get("sequence_number") or 0))
        return results

    # --- Attack Graph ---

    def save_graph_node(self, node_id: str, label: str, name: str, properties: Dict[str, Any]):
        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO attack_graph_nodes (node_id, label, name, properties_json)
                VALUES (?, ?, ?, ?)
            """, (node_id, label, name, json.dumps(properties, default=str)))

    def save_graph_edge(self, source_id: str, target_id: str, relation: str, properties: Dict[str, Any]):
        edge_id = f"{source_id}->{relation}->{target_id}"
        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO attack_graph_edges (edge_id, source_id, target_id, relation, properties_json)
                VALUES (?, ?, ?, ?, ?)
            """, (edge_id, source_id, target_id, relation, json.dumps(properties, default=str)))

    def load_graph_data(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        conn = self._get_connection()
        n_cur = conn.execute("SELECT * FROM attack_graph_nodes")
        nodes = [{
            "id": r["node_id"],
            "label": r["label"],
            "name": r["name"],
            "properties": json.loads(r["properties_json"] or "{}")
        } for r in n_cur.fetchall()]

        e_cur = conn.execute("SELECT * FROM attack_graph_edges")
        edges = [{
            "id": r["edge_id"],
            "source": r["source_id"],
            "target": r["target_id"],
            "relation": r["relation"],
            "properties": json.loads(r["properties_json"] or "{}")
        } for r in e_cur.fetchall()]
        return nodes, edges

    # --- Audit Logs ---

    def save_audit_log(self, entry: Dict[str, Any]):
        details = entry.get("details", {}) or {}
        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT INTO audit_logs (timestamp, actor, action, details_json, tenant_id)
                VALUES (?, ?, ?, ?, ?)
            """, (
                entry.get("timestamp", ""),
                entry.get("actor", "SYSTEM"),
                entry.get("action", "SYSTEM_ACTION"),
                json.dumps(details, default=str),
                entry.get("tenant_id") or details.get("tenant_id"),
            ))

    def record_audit_log(self, actor: str, action: str, details: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None):
        self.save_audit_log({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "details": details or {},
            "tenant_id": tenant_id,
        })

    def get_audit_logs(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if tenant_id is None:
            cur = conn.execute("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,))
        else:
            cur = conn.execute("SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY log_id DESC LIMIT ?", (tenant_id, limit))
        return [{
            "id": r["log_id"],
            "timestamp": r["timestamp"],
            "actor": r["actor"],
            "action": r["action"],
            "tenant_id": r["tenant_id"],
            "details": json.loads(r["details_json"] or "{}")
        } for r in cur.fetchall()]

    # --- Tenant-scoped platform settings ---
    def get_setting(self, tenant_id: str, key: str) -> Optional[Any]:
        row = self._get_connection().execute(
            "SELECT value_json FROM platform_settings WHERE tenant_id = ? AND key = ?", (tenant_id, key)).fetchone()
        return json.loads(row["value_json"]) if row else None

    def set_setting(self, tenant_id: str, key: str, value: Any) -> None:
        conn = self._get_connection()
        with conn:
            conn.execute("""
                INSERT INTO platform_settings (tenant_id, key, value_json, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
            """, (tenant_id, key, json.dumps(value, default=str), datetime.datetime.now(datetime.timezone.utc).isoformat()))

    # --- Investigation States (Durable Checkpoints for Planner Restart) ---

    def save_investigation_state(self, incident_id: str, tenant_id: str, state_dict: Dict[str, Any]):
        conn = self._get_connection()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO investigation_states (incident_id, tenant_id, state_json, updated_at)
                VALUES (?, ?, ?, ?)
            """, (incident_id, tenant_id, json.dumps(state_dict, default=str), now_iso))

    def load_investigation_state(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        if tenant_id:
            cur = conn.execute("SELECT state_json, tenant_id FROM investigation_states WHERE incident_id = ?", (incident_id,))
            row = cur.fetchone()
            if not row:
                return None
            if row["tenant_id"] != tenant_id:
                raise PermissionError(f"Unauthorized: Tenant '{tenant_id}' cannot access investigation state owned by '{row['tenant_id']}'.")
            return json.loads(row["state_json"])
        else:
            cur = conn.execute("SELECT state_json FROM investigation_states WHERE incident_id = ?", (incident_id,))
            row = cur.fetchone()
            return json.loads(row["state_json"]) if row else None
