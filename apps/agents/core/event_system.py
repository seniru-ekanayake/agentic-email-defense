"""
Real-Time Event Stream Module for FishingMails.
Emits granular, auditable lifecycle events for every agent decision, tool execution,
evidence creation, and state transition.
"""

import uuid
import datetime
import json
import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator
from pydantic import BaseModel, Field


class AgentLifecycleEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:10]}")
    investigation_id: str
    agent_run_id: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    sequence_number: int
    event_type: str  # agent.started, agent.step.started, agent.tool.selected, etc.
    status: str      # RUNNING, SUCCESS, FAILED, WAITING, etc.
    actor: str = "EmailSecurityInvestigator"
    tool: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    decision_id: Optional[str] = None
    message: str
    duration: Optional[float] = None
    error: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)

    def to_sse_payload(self) -> str:
        return f"event: {self.event_type}\ndata: {self.model_dump_json()}\n\n"


class EventStreamManager:
    """
    In-memory and persistent event ledger per investigation.
    Allows real-time subscription via async generators and historical replay.
    """
    _instance: Optional["EventStreamManager"] = None

    def __init__(self):
        self._investigation_events: Dict[str, List[AgentLifecycleEvent]] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._seq_counters: Dict[str, int] = {}

    @classmethod
    def get_instance(cls) -> "EventStreamManager":
        if cls._instance is None:
            cls._instance = EventStreamManager()
        return cls._instance

    def publish_event(
        self,
        investigation_id: str,
        agent_run_id: str,
        event_type: str,
        message: str,
        status: str = "INFO",
        actor: str = "EmailSecurityInvestigator",
        tool: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        decision_id: Optional[str] = None,
        duration: Optional[float] = None,
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> AgentLifecycleEvent:
        """Publishes a new event into the investigation ledger and dispatches to subscribers."""
        seq = self._seq_counters.get(investigation_id, 0) + 1
        self._seq_counters[investigation_id] = seq

        event = AgentLifecycleEvent(
            investigation_id=investigation_id,
            agent_run_id=agent_run_id,
            sequence_number=seq,
            event_type=event_type,
            status=status,
            actor=actor,
            tool=tool,
            evidence_ids=evidence_ids or [],
            decision_id=decision_id,
            message=message,
            duration=duration,
            error=error,
            data=data or {}
        )

        self._investigation_events.setdefault(investigation_id, []).append(event)

        # Notify active streaming subscribers
        if investigation_id in self._subscribers:
            for queue in self._subscribers[investigation_id]:
                try:
                    queue.put_nowait(event)
                except Exception:
                    pass

        return event

    def get_events(self, investigation_id: str) -> List[AgentLifecycleEvent]:
        """Returns all recorded events for an investigation."""
        return self._investigation_events.get(investigation_id, [])

    async def subscribe(self, investigation_id: str) -> AsyncGenerator[AgentLifecycleEvent, None]:
        """Subscribes an SSE consumer to real-time events for an active investigation."""
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(investigation_id, []).append(queue)

        # First flush any already recorded events
        existing = self._investigation_events.get(investigation_id, [])
        for ev in existing:
            yield ev

        try:
            while True:
                event = await queue.get()
                yield event
                if event.event_type in ["agent.completed", "agent.failed"]:
                    break
        finally:
            if investigation_id in self._subscribers and queue in self._subscribers[investigation_id]:
                self._subscribers[investigation_id].remove(queue)
