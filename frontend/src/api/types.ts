// 扫描请求
export interface ScanRequest {
  input_type: 'code' | 'path' | 'github'
  code?: string
  repo_path?: string
  repo_url?: string
  language?: string
}

// 扫描响应
export interface ScanResponse {
  scan_id: string
  summary: AuditSummary
  findings: FindingItem[]
  evidence: EvidenceItem[]
  agent_logs: AgentLogItem[]
  cve_candidates: CveCandidate[]
}

// 审计摘要
export interface AuditSummary {
  total_code_units: number
  total_findings: number
  total_evidence_bundles: number
  risk_score: number
  languages: string[]
  scanned_files: string[]
}

// 漏洞发现
export interface FindingItem {
  id: string
  type: string
  severity: string
  confidence: string
  file_path: string
  start_line: number
  end_line?: number
  message: string
  rule_id: string
  cwe?: string
  engine: string
  risk_score: number
  verdict: string
  snippet?: string
  call_chain: string[]
  metadata: Record<string, any>
}

// 证据包
export interface EvidenceItem {
  id: string
  scan_id: string
  finding_id?: string
  finding: FindingItem
  snippets: any[]
  call_chain: any[]
  agent_hypotheses: AgentHypothesis[]
  agent_logs: AgentLogItem[]
  judge_decision?: JudgeDecision
  cwe_info: Record<string, any>
  score_breakdown: Record<string, any>
}

// Agent 假设
export interface AgentHypothesis {
  id: string
  agent_name: string
  finding_id?: string
  hypothesis: string
  vulnerability_type?: string
  reasoning_summary: string
  confidence: string
  supporting_evidence_ids: string[]
}

// Agent 日志
export interface AgentLogItem {
  id: string
  scan_id: string
  agent_name: string
  stage: string
  message: string
  input_refs: string[]
  output_refs: string[]
  timestamp: string
  metadata: Record<string, any>
}

// Judge 裁决
export interface JudgeDecision {
  id: string
  finding_id: string
  verdict: string
  confidence: string
  risk_score: number
  reason: string
}

// CVE 候选
export interface CveCandidate {
  finding_id: string
  cve_id?: string
  cwe_id?: string
  score: number
  reasoning: string
}

// 任务信息
export interface TaskInfo {
  task_id: string
  state: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
  progress: number
  message: string
  error?: string
  scan_id?: string
  result?: ScanResponse
  created_at: string
  started_at?: string
  completed_at?: string
}

// 健康检查
export interface HealthStatus {
  status: string
}

// 认证状态
export interface AuthStatus {
  auth_enabled: boolean
  has_default_admin: boolean
}

// 扫描历史记录
export interface ScanRecord {
  scan_id: string
  project_id?: string
  summary_json: string
  metadata_json: string
  created_at: string
  updated_at: string
}

// 自主多模型调度 + 案例库自进化
export interface RoutingCandidate {
  provider: string
  model?: string
  local: boolean
  available: boolean
  allowed: boolean
  health: 'healthy' | 'degraded' | 'unavailable'
  score: number
  reasons: string[]
}

export interface RoutingDecision {
  decision_id: string
  created_at: string
  selected_provider: string
  selected_model?: string
  reason_codes: string[]
  fallback_chain: string[]
  execution_path: string[]
  candidates: RoutingCandidate[]
  context: Record<string, any>
  metadata: Record<string, any>
}

export interface RepairCase {
  case_id: string
  cwe?: string
  vulnerability_type: string
  language: string
  outcome: 'POSITIVE' | 'NEGATIVE'
  strategy: string
  trust_score: number
  failure_reason?: string
  retrieved_count: number
  successful_reuse_count: number
  metadata: Record<string, any>
  created_at: string
}

export interface CaseMatch {
  case: RepairCase
  similarity: number
  reasons: string[]
}

export interface CaseEvent {
  event_id: string
  case_id: string
  event_type: string
  scan_id?: string
  metadata: Record<string, any>
  created_at: string
}
