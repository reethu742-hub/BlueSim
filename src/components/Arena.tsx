import { useState } from "react";
import { Swords, Play, Loader2, CheckCircle2, XCircle, RotateCcw } from "lucide-react";
import { api } from "../api";
import type { ArenaScenario, ArenaAllResults } from "../types";

export function Arena() {
  const [scenarios, setScenarios] = useState<ArenaScenario[]>([]);
  const [results, setResults] = useState<ArenaAllResults | null>(null);
  const [running, setRunning] = useState(false);
  const [loadingScenarios, setLoadingScenarios] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadScenarios() {
    setLoadingScenarios(true);
    try {
      const { scenarios } = await api.getScenarios();
      setScenarios(scenarios);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scenarios");
    } finally {
      setLoadingScenarios(false);
    }
  }

  async function runAll() {
    setRunning(true);
    setError(null);
    try {
      const r = await api.runAllScenarios();
      setResults(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Arena run failed");
    } finally {
      setRunning(false);
    }
  }

  async function resetTests() {
    try {
      await api.resetTests();
      setResults(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Reset failed");
    }
  }

  const summary = results?.summary;
  const passRate = summary ? summary.total > 0 ? (summary.passed / summary.total * 100).toFixed(1) : "0.0" : "Not tested";

  return (
    <div className="card p-5 slide-up">
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <Swords className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">Red-Team vs Blue-Team Arena</h2>
        <span className="text-[10px] text-slate-500 uppercase tracking-wider">Real backend · Live verdicts</span>
      </div>

      <div className="flex gap-2 mb-4 flex-wrap">
        <button className="btn btn-ghost flex items-center gap-2" onClick={loadScenarios} disabled={loadingScenarios}>
          {loadingScenarios ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          Load Scenarios
        </button>
        <button className="btn btn-primary flex items-center gap-2" onClick={runAll} disabled={running}>
          {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Swords className="w-4 h-4" />}
          {running ? "Running All..." : "Run All Scenarios"}
        </button>
        {results && (
          <button className="btn btn-ghost flex items-center gap-2" onClick={resetTests}>
            <RotateCcw className="w-4 h-4" /> Reset
          </button>
        )}
      </div>

      {error && <p className="text-sm text-red-400 mb-3">{error}</p>}

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <Metric label="Demo Test-Suite Pass Rate" value={`${passRate}%`} highlight />
          <Metric label="Passed" value={`${summary.passed}/${summary.total}`} color="text-green-400" />
          <Metric label="False Approvals" value={String(summary.false_approvals)} color="text-red-400" />
          <Metric label="False Blocks" value={String(summary.false_blocks)} color="text-amber-400" />
          <Metric label="Benign Correct" value={`${summary.benign_passed}/${summary.benign_total}`} />
          <Metric label="Security Blocked" value={`${summary.security_passed}/${summary.security_total}`} />
          <Metric label="Failed" value={String(summary.failed)} color="text-red-400" />
        </div>
      )}

      {results && (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {results.results.map((r, i) => (
            <div key={i} className={`rounded-lg border p-3 text-xs ${
              r.passed ? "border-green-900/50 bg-green-950/10" : "border-red-900/50 bg-red-950/10"
            }`}>
              <div className="flex items-center gap-2 mb-1">
                {r.passed ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                <span className="font-medium text-slate-200">{r.scenario.name}</span>
                <span className={`badge text-[10px] ${
                  r.scenario.category === "benign" ? "bg-cyan-950 text-cyan-300" : "bg-red-950 text-red-300"
                }`}>{r.scenario.category}</span>
                <span className={`badge text-[10px] ${
                  r.passed ? "bg-green-900 text-green-200" : "bg-red-900 text-red-200"
                }`}>{r.passed ? "PASS" : "FAIL"}</span>
              </div>
              <div className="text-slate-400 text-[11px]">
                Expected: {r.scenario.expected} → Actual: {r.actual}
              </div>
              <div className="text-slate-500 text-[11px] mt-0.5">{r.explanation}</div>
            </div>
          ))}
        </div>
      )}

      {scenarios.length > 0 && !results && (
        <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
          {scenarios.map((s) => (
            <div key={s.id} className="rounded-lg bg-slate-950/40 border border-slate-800 p-2.5 text-xs">
              <div className="flex items-center gap-2">
                <span className={`badge text-[10px] ${s.category === "benign" ? "bg-cyan-950 text-cyan-300" : "bg-red-950 text-red-300"}`}>{s.category}</span>
                <span className="text-slate-200 font-medium">{s.name}</span>
                <span className="text-slate-500 ml-auto">Expected: {s.expected}</span>
              </div>
              <div className="text-slate-500 mt-1 text-[11px] truncate">{s.request}</div>
            </div>
          ))}
        </div>
      )}

      {!scenarios.length && !results && !error && (
        <div className="text-center py-6 text-slate-500 text-sm">
          Load scenarios to see the test suite, or run all to execute the full arena.
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, color, highlight }: { label: string; value: string; color?: string; highlight?: boolean }) {
  return (
    <div className={`rounded-lg p-3 border ${highlight ? "border-cyan-800 bg-cyan-950/20" : "border-slate-800 bg-slate-950/30"}`}>
      <div className={`text-lg font-bold ${color || "text-white"}`}>{value}</div>
      <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
    </div>
  );
}
