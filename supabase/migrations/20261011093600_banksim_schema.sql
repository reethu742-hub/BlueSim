/*
# BankSim: Blue-Team AI Firewall — Database Schema

## Purpose
Creates the fictional banking simulation database for a cybersecurity hackathon prototype.
All data is fictional — no real banking, no real money, no real customer data.

## New Tables
1. `accounts` — Fictional bank accounts with balances stored in paise (integer minor units).
2. `transactions` — Mock transaction history.
3. `confirmations` — Pending transfer confirmation state.
4. `audit_events` — Tamper-evident SHA-256 hash-chained security ledger.
5. `test_runs` — Arena test run records for statistics.

## Security
- RLS enabled on all tables. No-auth demo app — all policies use `TO anon, authenticated`.
- Data is intentionally public/shared (fictional demo data).

## Notes
1. Money stored as integer paise (bigint) — never floating-point.
2. SHA-256 hash chain on audit_events with documented initial hash constant.
3. All state is backend-authoritative.
*/

-- Accounts table
CREATE TABLE IF NOT EXISTS accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  balance_paise bigint NOT NULL DEFAULT 0,
  is_demo boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_accounts" ON accounts;
CREATE POLICY "anon_select_accounts" ON accounts FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_accounts" ON accounts;
CREATE POLICY "anon_insert_accounts" ON accounts FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_accounts" ON accounts;
CREATE POLICY "anon_update_accounts" ON accounts FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_accounts" ON accounts;
CREATE POLICY "anon_delete_accounts" ON accounts FOR DELETE
  TO anon, authenticated USING (true);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_account text NOT NULL,
  to_account text NOT NULL,
  amount_paise bigint NOT NULL,
  memo text,
  status text NOT NULL DEFAULT 'COMPLETED',
  request_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_transactions" ON transactions;
CREATE POLICY "anon_select_transactions" ON transactions FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_transactions" ON transactions;
CREATE POLICY "anon_insert_transactions" ON transactions FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_transactions" ON transactions;
CREATE POLICY "anon_update_transactions" ON transactions FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_transactions" ON transactions;
CREATE POLICY "anon_delete_transactions" ON transactions FOR DELETE
  TO anon, authenticated USING (true);

-- Confirmations table
CREATE TABLE IF NOT EXISTS confirmations (
  id text PRIMARY KEY,
  from_account text NOT NULL,
  to_account text NOT NULL,
  amount_paise bigint NOT NULL,
  action text NOT NULL,
  memo text,
  status text NOT NULL DEFAULT 'PENDING',
  request_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  confirmed_at timestamptz
);

ALTER TABLE confirmations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_confirmations" ON confirmations;
CREATE POLICY "anon_select_confirmations" ON confirmations FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_confirmations" ON confirmations;
CREATE POLICY "anon_insert_confirmations" ON confirmations FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_confirmations" ON confirmations;
CREATE POLICY "anon_update_confirmations" ON confirmations FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_confirmations" ON confirmations;
CREATE POLICY "anon_delete_confirmations" ON confirmations FOR DELETE
  TO anon, authenticated USING (true);

-- Audit events table (tamper-evident ledger)
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id text NOT NULL,
  event_timestamp timestamptz NOT NULL DEFAULT now(),
  sanitized_request text,
  verdict text NOT NULL,
  threat_category text,
  risk_score integer,
  requested_action text,
  execution_result text,
  previous_hash text NOT NULL,
  current_hash text NOT NULL,
  event_data jsonb
);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_audit_events" ON audit_events;
CREATE POLICY "anon_select_audit_events" ON audit_events FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_audit_events" ON audit_events;
CREATE POLICY "anon_insert_audit_events" ON audit_events FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_audit_events" ON audit_events;
CREATE POLICY "anon_update_audit_events" ON audit_events FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_audit_events" ON audit_events;
CREATE POLICY "anon_delete_audit_events" ON audit_events FOR DELETE
  TO anon, authenticated USING (true);

-- Test runs table
CREATE TABLE IF NOT EXISTS test_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id text NOT NULL,
  scenario_name text NOT NULL,
  category text NOT NULL,
  expected_result text NOT NULL,
  actual_result text NOT NULL,
  passed boolean NOT NULL,
  explanation text,
  request_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE test_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_test_runs" ON test_runs;
CREATE POLICY "anon_select_test_runs" ON test_runs FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_test_runs" ON test_runs;
CREATE POLICY "anon_insert_test_runs" ON test_runs FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_test_runs" ON test_runs;
CREATE POLICY "anon_delete_test_runs" ON test_runs FOR DELETE
  TO anon, authenticated USING (true);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_transactions_from_account ON transactions(from_account);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_timestamp ON audit_events(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_confirmations_status ON confirmations(status);

-- Seed initial fictional accounts
INSERT INTO accounts (name, balance_paise, is_demo) VALUES
  ('Main Demo Account', 5000000, true),
  ('Rahul', 75000, false),
  ('Priya', 120000, false),
  ('Arjun', 30000, false),
  ('Merchant Demo Account', 1000000, false)
ON CONFLICT (name) DO NOTHING;
