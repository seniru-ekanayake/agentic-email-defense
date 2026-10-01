"""
Agent State Machine Module for FishingMails.
Implements the 17+ explicit operational states, transition validation,
pause/resume/cancel controls, and external dependency waiting states.
"""

from enum import Enum
import time
import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AgentState(str, Enum):
    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    PARSING = "PARSING"
    EXTRACTING_EVIDENCE = "EXTRACTING_EVIDENCE"
    FORMING_HYPOTHESES = "FORMING_HYPOTHESES"
    INVESTIGATING = "INVESTIGATING"
    WAITING_FOR_TOOL = "WAITING_FOR_TOOL"
    WAITING_FOR_EXTERNAL_SERVICE = "WAITING_FOR_EXTERNAL_SERVICE"
    ANALYZING_RESULT = "ANALYZING_RESULT"
    TOOL_FAILURE = "TOOL_FAILURE"
    REASSESSING = "REASSESSING"
    ESCALATING = "ESCALATING"
    GENERATING_VERDICT = "GENERATING_VERDICT"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    EXECUTING_RESPONSE = "EXECUTING_RESPONSE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"
    PAUSED = "PAUSED"


class StateTransition(BaseModel):
    from_state: AgentState
    to_state: AgentState
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    reason: Optional[str] = None
    duration_in_previous_state_ms: float = 0.0


class InvestigationStateMachine:
    """
    Manages the lifecycle and transitions of an active email investigation.
    Ensures that every transition is audited, validated, and observable.
    """

    TERMINAL_STATES = {
        AgentState.COMPLETED,
        AgentState.FAILED,
        AgentState.CANCELLED,
        AgentState.TIMEOUT
    }

    def __init__(self, investigation_id: str):
        self.investigation_id = investigation_id
        self.current_state: AgentState = AgentState.QUEUED
        self.transitions: List[StateTransition] = []
        self._last_transition_time = time.time()
        self._paused_previous_state: Optional[AgentState] = None
        self._is_paused: bool = False

    def transition_to(self, new_state: AgentState, reason: Optional[str] = None) -> StateTransition:
        """Transitions to a new state and records execution timing."""
        if self.current_state in self.TERMINAL_STATES:
            raise ValueError(f"Cannot transition from terminal state {self.current_state} to {new_state}")

        now = time.time()
        duration_ms = (now - self._last_transition_time) * 1000.0
        self._last_transition_time = now

        transition = StateTransition(
            from_state=self.current_state,
            to_state=new_state,
            reason=reason,
            duration_in_previous_state_ms=round(duration_ms, 2)
        )
        self.transitions.append(transition)
        self.current_state = new_state
        return transition

    def pause(self, reason: str = "Paused by security analyst") -> StateTransition:
        """Pauses the investigation state machine."""
        if self.current_state in self.TERMINAL_STATES or self.current_state == AgentState.PAUSED:
            raise ValueError(f"Cannot pause investigation in state {self.current_state}")
        self._paused_previous_state = self.current_state
        self._is_paused = True
        return self.transition_to(AgentState.PAUSED, reason=reason)

    def resume(self, reason: str = "Resumed by security analyst") -> StateTransition:
        """Resumes a paused investigation."""
        if self.current_state != AgentState.PAUSED or not self._paused_previous_state:
            raise ValueError("Investigation is not paused")
        target_state = self._paused_previous_state
        self._paused_previous_state = None
        self._is_paused = False
        return self.transition_to(target_state, reason=reason)

    def cancel(self, reason: str = "Cancelled by security analyst") -> StateTransition:
        """Cancels an active investigation."""
        return self.transition_to(AgentState.CANCELLED, reason=reason)

    def mark_waiting_external(self, service_name: str) -> StateTransition:
        """Indicates that agent is awaiting external threat feed or API."""
        return self.transition_to(AgentState.WAITING_FOR_EXTERNAL_SERVICE, reason=f"Waiting for {service_name}")

    def mark_tool_failure(self, tool_name: str, error: str) -> StateTransition:
        """Explicitly flags a tool failure instead of hiding behind a generic message."""
        return self.transition_to(AgentState.TOOL_FAILURE, reason=f"{tool_name} failed: {error}")

    def is_active(self) -> bool:
        return self.current_state not in self.TERMINAL_STATES and self.current_state != AgentState.PAUSED

    def get_history(self) -> List[Dict[str, Any]]:
        return [t.model_dump() for t in self.transitions]
