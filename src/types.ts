export type ThreatCategory =
  | "NONE"
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "ROLEPLAY_ATTACK"
  | "MALICIOUS_MEMO"
  | "OBFUSCATION"
  | "INTENT_MISMATCH"
  | "INVALID_TRANSACTION"
  | "UNAUTHORIZED_ACTION"
  | "AMBIGUOUS_REQUEST";

export type VerdictStatus = "APPROVED" | "BLOCKED" | "REVIEW" | "CONFIRMATION_REQUIRED";

export interface Finding {
  category: ThreatCategory;
  evidence: string;
  rule: string;
  explanation: string;
}

export interface ParsedTransaction {
  action: string | null;
  amount_paise: number | null;
  beneficiary: string | null;
  memo: string | null;
}

export interface SecurityVerdict {
  request_id: string;
  status: VerdictStatus;
  risk_score: number;
  risk_level: string;
  threat_category: ThreatCategory;
  action: string | null;
  explanation: string;
  execution_allowed: boolean;
  executed: boolean;
  timestamp: string;
  amount_paise: number | null;
  beneficiary: string | null;
  findings: Finding[];
  parsed: ParsedTransaction;
  normalized_text: string;
  original_text: string;
  confirmation_id: string | null;
  execution_result: string | null;
  actual_amount_transferred_paise: number;
  balances_changed: boolean;
}

export interface Account {
  name: string;
  balance_paise: number;
  is_demo: boolean;
  balance_display: string;
}

export interface Transaction {
  id: string;
  from_account: string;
  to_account: string;
  amount_paise: number;
  amount_display: string;
  memo: string | null;
  status: string;
  request_id: string | null;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  request_id: string;
  event_timestamp: string;
  sanitized_request: string | null;
  verdict: string;
  threat_category: string | null;
  risk_score: number | null;
  requested_action: string | null;
  execution_result: string | null;
  previous_hash: string;
  current_hash: string;
  event_data: Record<string, unknown> | null;
}

export interface ArenaScenario {
  id: string;
  name: string;
  category: "benign" | "security";
  request: string;
  expected: string;
  expected_description: string;
}

export interface ArenaResult {
  scenario: ArenaScenario;
  verdict: SecurityVerdict;
  result: {
    passed: boolean;
    explanation: string;
    expected: string;
    actual: string;
  };
  balances_before: number;
  balances_after: number;
  balances_unchanged: boolean;
}

export interface ArenaAllResults {
  results: Array<{
    scenario: ArenaScenario;
    passed: boolean;
    explanation: string;
    actual: string;
    verdict: SecurityVerdict;
  }>;
  summary: {
    total: number;
    passed: number;
    failed: number;
    pass_rate: number;
    benign_passed: number;
    benign_total: number;
    security_passed: number;
    security_total: number;
    false_approvals: number;
    false_blocks: number;
  };
}

export interface DashboardStats {
  requests_inspected: number;
  threats_detected: number;
  transactions_blocked: number;
  transactions_executed: number;
  fictional_money_protected_paise: number;
  fictional_money_protected_display: string;
  test_pass_rate: number | null;
  test_total: number;
  test_passed: number;
  benign_passed: number;
  benign_total: number;
  security_passed: number;
  security_total: number;
  false_approvals: number;
  false_blocks: number;
}

export interface BlastRadiusResult {
  verdict: SecurityVerdict;
  simulation: {
    source_balance_before: number | null;
    attempted_amount: number | null;
    executable_amount: number | null;
    hypothetical_remaining_balance: number | null;
    hypothetical_exposure_percentage: number | null;
    actual_amount_transferred: number;
    actual_loss: number;
    money_protected: number | null;
    target_account: string | null;
    affected_accounts: number;
    source_balance_before_display: string;
    attempted_amount_display: string;
    executable_amount_display: string;
    hypothetical_remaining_balance_display: string;
    actual_amount_transferred_display: string;
    actual_loss_display: string;
    money_protected_display: string;
    hypothetical_exposure_percentage_display: string;
  };
  accounts_after: Account[];
  note: string;
}

export interface ChainVerification {
  valid: boolean;
  errors: string[];
  total_events: number;
}

export interface TamperDemoResult {
  original_valid: boolean;
  tampered_valid: boolean;
  tampered_event: string;
  original_errors: string[];
  tampered_errors: string[];
}
