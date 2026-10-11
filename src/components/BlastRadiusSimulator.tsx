import { useState } from "react";
import { Zap, Loader2, Shield, Crosshair, CheckCircle2 } from "lucide-react";
import { api } from "../api";
import type { BlastRadiusResult } from "../types";

export function BlastRadiusSimulator() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BlastRadiusResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function simulate() {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const r = await api.blastRadius(text);
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Simulation failed");
    } finally {
      setLoading(false);
    }
  }

  const sim = result?.simulation;
  const v = result?.verdict;

  return (
    <div className="card p-5 slide-up">
      <div className="flex items-center gap-2 mb-4">
        <Crosshair className="w-5 h-5 text-red-400" />
        <h2 className="text-base font-semibold text-white">Blast-Radius Simulator</h2>
        <span className="text-[10px] text-slate-500 ml-auto uppercase tracking-wider">Counterfactual · Read-Only</span>
      </div>

      <div className="flex gap-2 mb-4">
        <input
          className="input flex-1 text-sm"
          placeholder="Enter an attack request to simulate..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && simulate()}
        />
        <button
          className="btn btn-primary flex items-center gap-2 whitespace-nowrap"
          onClick={simulate}
          disabled={loading || !text.trim()}
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          Simulate
        </button>
      </div>

      {error && <p className="text-sm text-red-400 mb-3">{error}</p>}

      {sim && v && (
        <div className="space-y-4 fade-in">
          {/* BEFORE ATTACK */}
          <div className="rounded-lg border border-slate-700 bg-slate-950/40 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Before Attack</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-slate-500 text-xs">Source Balance</span>
                <div className="text-white font-semibold">{sim.source_balance_before_display}</div>
              </div>
              <div>
                <span className="text-slate-500 text-xs">Attempted Amount</span>
                <div className="text-red-300 font-semibold">{sim.attempted_amount_display}</div>
              </div>
            </div>
          </div>

          {/* FIREWALL INTERCEPTION */}
          <div className={`rounded-lg border p-4 ${
            v.status === "BLOCKED" ? "border-red-800 bg-red-950/20" : "border-amber-800 bg-amber-950/20"
          }`}>
            <div className="flex items-center gap-2 mb-2">
              <Shield className={`w-4 h-4 ${v.status === "BLOCKED" ? "text-red-400" : "text-amber-400"}`} />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">Firewall Interception</h3>
            </div>
            <div className="text-sm">
              <span className={`badge ${v.status === "BLOCKED" ? "bg-red-900 text-red-200" : "bg-amber-900 text-amber-200"}`}>
                {v.status}
              </span>
              <span className="text-slate-400 ml-2 text-xs">{v.threat_category}</span>
            </div>
            <p className="text-xs text-slate-400 mt-2">{v.explanation}</p>
          </div>

          {/* AFTER DEFENCE */}
          <div className="rounded-lg border border-green-800 bg-green-950/20 p-4">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <h3 className="text-xs font-semibold text-green-400 uppercase tracking-wider">After Defence — Balances Unchanged</h3>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-slate-500 text-xs">Actual Transfer</span>
                <div className="text-green-300 font-semibold">{sim.actual_amount_transferred_display}</div>
              </div>
              <div>
                <span className="text-slate-500 text-xs">Actual Loss</span>
                <div className="text-green-300 font-semibold">{sim.actual_loss_display}</div>
              </div>
            </div>
          </div>

          {/* HYPOTHETICAL IMPACT */}
          <div className="rounded-lg border border-slate-700 bg-slate-950/40 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Hypothetical Impact <span className="text-red-400">(if the firewall were absent)</span>
            </h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <HypotheticalItem label="Executable Amount" value={sim.executable_amount_display} />
              <HypotheticalItem label="Remaining Balance" value={sim.hypothetical_remaining_balance_display} />
              <HypotheticalItem label="Exposure %" value={sim.hypothetical_exposure_percentage_display} />
              <HypotheticalItem label="Money Protected" value={sim.money_protected_display} highlight />
              <HypotheticalItem label="Target Account" value={sim.target_account || "UNKNOWN"} />
              <HypotheticalItem label="Affected Accounts" value={String(sim.affected_accounts)} />
            </div>
          </div>

          <p className="text-[11px] text-slate-500 italic">
            {result?.note} All hypothetical figures are counterfactual estimates based on the parsed request.
          </p>
        </div>
      )}

      {!result && !error && (
        <div className="text-center py-6 text-slate-500 text-sm">
          Enter an attack request above to simulate the potential blast radius.
        </div>
      )}
    </div>
  );
}

function HypotheticalItem({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div>
      <span className="text-slate-500 text-xs">{label}</span>
      <div className={`font-semibold ${highlight ? "text-green-300" : "text-slate-200"}`}>{value}</div>
    </div>
  );
}
