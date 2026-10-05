/**
 * Strongly typed schema definitions mirroring backend FishingMails models
 * Source of truth: apps/server.py and apps/agents/
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type IncidentStatus = 'CREATED' | 'INVESTIGATING' | 'PAUSED' | 'CANCELLED' | 'CONTAINMENT_PROPOSED' | 'CONTAINMENT_APPROVED' | 'CONTAINMENT_REJECTED' | 'CLOSED';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface AttackChainStep {
  step?: number;
  stage?: string;
  technique?: string;
  description?: string;
  node?: string;
  type?: string;
}

export interface RecommendedAction {
  name?: string;
  action?: string;
  risk?: string;
  reasoning?: string;
  automated?: boolean;
  requires_approval?: boolean;
}

export interface PendingApproval {
  tool_name: string;
  parameters: Record<string, any>;
  reasoning: string;
  approval_token: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface GraphNode {
  id: string;
  label?: string;
  name?: string;
  type?: string;
  properties?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  properties?: Record<string, any>;
}

export interface GraphContext {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface EvidenceItem {
  evidence_id: string;
  type: string;
  value: string;
  source: string;
  timestamp: string;
  confidence: string;
  status: string;
  metadata?: Record<string, any>;
}

export interface Hypothesis {
  hypothesis_id: string;
  statement: string;
  status: string;
  category: string;
  evidence_ids: string[];
  updated_at?: string;
}

export interface DecisionRecord {
  decision_id: string;
  observed: string;
  evidence_ids: string[];
  decision: string;
  action: string;
  reason: string;
  result: string;
  impact?: string;
  confidence: string;
  timestamp: string;
  trigger_evidence_ids?: string[];
  hypothesis_tested?: string;
  alternatives_considered?: string[];
  tool_selected_rationale?: string;
  inputs_rationale?: string;
  result_observed?: string;
  belief_state_impact?: string;
  next_planned_action?: string;
}

export interface ToolExecutionRecord {
  execution_id: string;
  tool_name: string;
  status: 'COMPLETED' | 'FAILED' | 'RUNNING' | 'SKIPPED';
  input_parameters: Record<string, any>;
  started_at: string;
  completed_at?: string | null;
  duration_ms: number;
  result_summary: string;
  raw_response?: string;
  normalized_response?: Record<string, any>;
  evidence_created?: string[];
  source?: string;
  confidence?: string;
  error?: string | null;
}

export interface RiskAdjustment {
  component: string;
  delta: number;
  reason: string;
  evidence_id?: string;
  resulting_score: number;
}

export interface RiskProvenance {
  baseline_score: number;
  final_score: number;
  adjustments: RiskAdjustment[];
}

export interface TrustScoreComponent {
  name: string;
  weight: number;
  score: number;
  weighted_score: number;
  metric_value: string;
  rationale: string;
}

export interface TrustScore {
  overall_score: number;
  grade: string;
  components: TrustScoreComponent[];
  unsupported_claim_count?: number;
  total_claims_evaluated?: number;
  total_tools_executed?: number;
  failed_tools_count?: number;
}

export interface AgentDecisionState {
  current_objective: string;
  evidence_considered_count: number;
  tools_available_count: number;
  tools_executed_count: number;
  tools_remaining_count: number;
  current_hypothesis: string;
  next_action: string;
  reason: string;
  expected_information_gain: string;
  risk_level: string;
  timeout_remaining: string;
}

export interface ComprehensiveIncidentRecord {
  incident_id: string;
  tenant_id: string;
  title: string;
  severity: SeverityLevel;
  overall_risk_score: number;
  confidence: number;
  status: IncidentStatus;
  sender: string;
  recipient: string;
  subject: string;
  target_identity: string;
  mail_platform: string;
  exposure_status: string;
  interaction_required: string;
  cve?: string;
  threat_category: string;
  timestamp: string;
  attack_chain: AttackChainStep[];
  mitre_techniques: MitreTechnique[];
  evidence_summary: string[];
  recommended_actions: RecommendedAction[];
  pending_approvals: PendingApproval[];
  graph_context: GraphContext;
  evidence_items: EvidenceItem[];
  hypotheses: Hypothesis[];
  decision_trace: DecisionRecord[];
  tool_executions: ToolExecutionRecord[];
  forensic_audit?: Record<string, any>;
  claim_evidence_items?: any[];
  evidence_graph?: Record<string, any>;
  risk_provenance?: RiskProvenance;
  explanation?: string;
  telemetry?: Record<string, any>;
  trust_score?: TrustScore;
  agent_decision_state?: AgentDecisionState;
  state_history?: any[];
  events?: AgentLifecycleEvent[];
  created_at: string;
  updated_at: string;
}

export interface AgentLifecycleEvent {
  event_id: string;
  investigation_id: string;
  agent_run_id: string;
  timestamp: string;
  sequence_number: number;
  event_type: string;
  status: string;
  actor: string;
  tool?: string | null;
  evidence_ids: string[];
  decision_id?: string | null;
  message: string;
  duration?: number | null;
  error?: string | null;
  data: Record<string, any>;
}

export interface SystemHealthResponse {
  status: 'HEALTHY' | 'DEGRADED';
  timestamp: string;
  mode: string;
  is_production: boolean;
  mock_mode: string;
  demo_fixtures: string;
  subsystems: Record<string, string>;
}

export interface ApprovalResponse {
  status: 'SUCCESS' | 'REJECTED' | 'ERROR';
  message: string;
  output?: any;
}
