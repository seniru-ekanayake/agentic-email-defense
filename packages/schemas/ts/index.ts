/**
 * Canonical TypeScript types for the Email Exploitation Detection & Response Platform.
 * Mirrors packages/schemas/python/models.py and the canonical JSON schemas.
 */

export enum DataClassification {
  PUBLIC = "PUBLIC",
  INTERNAL = "INTERNAL",
  CONFIDENTIAL = "CONFIDENTIAL",
  RESTRICTED = "RESTRICTED"
}

export enum InteractionRequirement {
  NONE = "NONE",
  VIEW = "VIEW",
  HOVER = "HOVER",
  CLICK = "CLICK",
  OPEN_ATTACHMENT = "OPEN_ATTACHMENT",
  EXECUTE_ATTACHMENT = "EXECUTE_ATTACHMENT",
  MULTI_STEP = "MULTI_STEP"
}

export enum RiskLevel {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

export enum ApprovalRequirement {
  AUTOMATIC = "AUTOMATIC",
  POLICY_DEPENDENT = "POLICY_DEPENDENT",
  MANDATORY_HUMAN = "MANDATORY_HUMAN"
}

export interface SenderInfo {
  address: string;
  display_name?: string;
  domain?: string;
}

export interface RecipientInfo {
  address: string;
  display_name?: string;
  type: "to" | "cc" | "bcc";
}

export interface AuthenticationResults {
  spf: "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror";
  dkim: "pass" | "fail" | "none" | "temperror" | "permerror";
  dmarc: "pass" | "fail" | "none" | "temperror" | "permerror";
  auth_results_raw?: string;
}

export interface MimeStructure {
  content_type?: string;
  boundary?: string;
  structure_depth: number;
  is_multipart: boolean;
  parts_summary: string[];
  malformed_indicators: string[];
}

export interface HtmlFeatures {
  has_forms: boolean;
  has_scripts: boolean;
  has_iframes: boolean;
  has_svg_xml: boolean;
  has_external_css: boolean;
  has_remote_images: boolean;
  hidden_elements_count: number;
  suspicious_tags: string[];
}

export interface BodyFeatures {
  text_plain?: string;
  text_html?: string;
  html_features?: HtmlFeatures;
}

export interface UrlFeature {
  url: string;
  domain: string;
  display_text?: string;
  is_mismatched: boolean;
  is_ip_based: boolean;
  is_punycode: boolean;
  reputation?: string;
}

export interface AttachmentFeature {
  filename: string;
  content_type: string;
  sha256: string;
  size_bytes: number;
  magic_type?: string;
  is_executable: boolean;
  has_macros: boolean;
  archive_contents: string[];
}

export interface ExploitIndicator {
  indicator_type: string;
  evidence: string;
  target_software?: string;
  target_cve?: string;
  confidence: number;
}

export interface IdentityTarget {
  email: string;
  user_id?: string;
  department?: string;
  is_vip: boolean;
  privilege_level?: string;
}

export interface RiskEvidence {
  factor: string;
  score_impact: number;
  reasoning: string;
}

export interface EmailAttackRepresentation {
  message_id: string;
  timestamp: string;
  sender: SenderInfo;
  recipients: RecipientInfo[];
  authentication: AuthenticationResults;
  headers: Record<string, string>;
  mime: MimeStructure;
  body: BodyFeatures;
  urls: UrlFeature[];
  attachments: AttachmentFeature[];
  embedded_content: Record<string, any>[];
  rendering_features: string[];
  parser_features: string[];
  behavioral_features: string[];
  exploit_indicators: ExploitIndicator[];
  identity_targets: IdentityTarget[];
  classification: DataClassification;
  risk_evidence: RiskEvidence[];
}

export interface EmailExploitabilityAssessment {
  cve: string;
  affected_product: string;
  affected_component: string;
  attack_vector: string;
  email_delivery_possible: boolean;
  rendering_required: boolean;
  interaction_required: InteractionRequirement;
  authentication_required: boolean;
  session_impact: string;
  likely_post_exploitation: string[];
  evidence: string[];
  confidence: number;
}

export interface ToolDefinition {
  name: string;
  description: string;
  risk_level: RiskLevel;
  required_permission: string;
  approval_requirement: ApprovalRequirement;
  input_schema: Record<string, any>;
  output_schema: Record<string, any>;
  audit_required: boolean;
}

export interface ToolProposal {
  tool_name: string;
  parameters: Record<string, any>;
  reasoning: string;
  confidence: number;
}

export interface ToolExecutionResult {
  tool_name: string;
  success: boolean;
  executed: boolean;
  requires_human_approval: boolean;
  approval_token?: string;
  output?: Record<string, any>;
  error?: string;
  audit_id: string;
}
