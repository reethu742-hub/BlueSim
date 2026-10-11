import { useState, useEffect, useCallback } from "react";
import { api } from "./api";
import type { SecurityVerdict, DashboardStats, Account } from "./types";
import { TopStatusBar } from "./components/TopStatusBar";
import { SecurityOverview } from "./components/SecurityOverview";
import { RequestAnalyser } from "./components/RequestAnalyser";
import { KillSwitch } from "./components/KillSwitch";
import { BlastRadiusSimulator } from "./components/BlastRadiusSimulator";
import { AttackAutopsy } from "./components/AttackAutopsy";
import { Arena } from "./components/Arena";
import { IntentLock } from "./components/IntentLock";
import { SecurityLedger } from "./components/SecurityLedger";
import { DemoControls } from "./components/DemoControls";

type ConnectionState = "checking" | "connected" | "disconnected";

function App() {
  const [verdict, setVerdict] = useState<SecurityVerdict | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("checking");
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);

  const loadStats = useCallback(async () => {
    try {
      const s = await api.getStats();
      setStats(s);
    } catch (e) {
      setConnectionError(e instanceof Error ? e.message : "Failed to load stats");
    }
  }, []);

  const checkChain = useCallback(async () => {
    try {
      const r = await api.verifyChain();
      setAuditValid(r.valid);
    } catch {
      setAuditValid(null);
    }
  }, []);

  const loadAccounts = useCallback(async () => {
    try {
      const { accounts } = await api.getAccounts();
      setAccounts(accounts);
    } catch {
      // Non-critical
    }
  }, []);

  useEffect(() => {
    async function init() {
      try {
        await api.health();
        setConnection("connected");
        setConnectionError(null);
        await Promise.all([loadStats(), checkChain(), loadAccounts()]);
      } catch (e) {
        setConnection("disconnected");
        setConnectionError(e instanceof Error ? e.message : "Cannot reach backend");
      }
    }
    init();
  }, [loadStats, checkChain, loadAccounts]);

  function handleVerdict(v: SecurityVerdict) {
    setVerdict(v);
    loadStats();
    checkChain();
  }

  function handleReset() {
    setVerdict(null);
    loadStats();
    loadAccounts();
  }

  const firewallActive = connection === "connected";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <TopStatusBar auditChainValid={auditValid} firewallActive={firewallActive} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Connection error banner */}
        {connection === "disconnected" && (
          <div className="rounded-lg border border-red-800 bg-red-950/40 p-4 flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse flex-shrink-0" />
            <div>
              <div className="text-sm font-semibold text-red-300">
                Cannot connect to the BankSim backend
              </div>
              <div className="text-xs text-red-400 mt-0.5">
                {connectionError || "Unknown error"}. The edge function may still be starting up — refresh the page in a few seconds.
              </div>
            </div>
            <button
              className="btn btn-ghost ml-auto text-xs"
              onClick={() => window.location.reload()}
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading state */}
        {connection === "checking" && (
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-cyan-500 animate-pulse flex-shrink-0" />
            <div className="text-sm text-slate-300">
              Connecting to BankSim security engine...
            </div>
          </div>
        )}

        {/* Hero banner */}
        <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-6">
          <div className="relative z-10">
            <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
              BankSim: Blue-Team AI Firewall
            </h1>
            <p className="text-sm text-slate-400 mt-2 max-w-2xl">
              Detect the attack. Stop the transaction. Prove the defence. A deterministic security
              firewall for a fictional banking simulation — intercepting, inspecting, and blocking
              adversarial inputs before any mock transaction can execute.
            </p>
            <div className="flex gap-2 mt-3 flex-wrap">
              <span className="badge bg-cyan-950/50 text-cyan-300 border border-cyan-900">Rule-Based Detection</span>
              <span className="badge bg-slate-800 text-slate-300 border border-slate-700">Fictional Money</span>
              <span className="badge bg-green-950/50 text-green-300 border border-green-900">Backend-Authoritative</span>
              <span className="badge bg-amber-950/50 text-amber-300 border border-amber-900">SHA-256 Audit Chain</span>
            </div>

            {/* Quick account summary */}
            {accounts.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-3">
                {accounts.map((a) => (
                  <div key={a.name} className="px-3 py-1.5 rounded-lg bg-slate-950/50 border border-slate-800 text-xs">
                    <span className="text-slate-500">{a.is_demo ? "DEMO: " : ""}{a.name}</span>
                    <span className="text-slate-200 font-mono ml-2">{a.balance_display}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="absolute right-0 top-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute right-10 bottom-0 w-48 h-48 bg-blue-500/5 rounded-full blur-3xl" />
        </div>

        {/* Security Overview Metrics */}
        <SecurityOverview stats={stats} />

        {/* Main grid: analyser + kill switch */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <RequestAnalyser onVerdict={handleVerdict} />
          <KillSwitch verdict={verdict} />
        </div>

        {/* Blast radius + Autopsy */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <BlastRadiusSimulator />
          <AttackAutopsy verdict={verdict} />
        </div>

        {/* Intent lock + Arena */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <IntentLock verdict={verdict} />
          <Arena />
        </div>

        {/* Ledger + Demo controls */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SecurityLedger />
          <DemoControls onReset={handleReset} onVerdict={handleVerdict} onStatsUpdate={loadStats} />
        </div>

        {/* Footer */}
        <footer className="border-t border-slate-800 pt-4 pb-8 text-center">
          <p className="text-xs text-slate-500">
            BankSim is a defensive cybersecurity prototype using fictional accounts and mock balances.
            This is not a certified production banking firewall. All threat detection is rule-based.
          </p>
        </footer>
      </main>
    </div>
  );
}

export default App;
