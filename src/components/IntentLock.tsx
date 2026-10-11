import { Lock } from "lucide-react";
import type { SecurityVerdict } from "../types";

interface Props {
  verdict: SecurityVerdict | null;
}

export function IntentLock({ verdict }: Props) {
  const formatPaise = (p: number | null) => p !== null ? `₹${(p / 100).toLocaleString("en-IN", { minimumFractionDigits: 2 })}` : "UNRESOLVED";

  const hasIntentMismatch = verdict?.findings.some(f => f.category === "INTENT_MISMATCH") ?? false;

  return (
    <div className="card p-5 slide-up">
      <div className="flex items-center gap-2 mb-4">
        <Lock className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">Transaction Intent Lock</h2>
      </div>

      {!verdict ? (
        <div className="text-center py-6 text-slate-500 text-sm">Submit a request to see intent analysis.</div>
      ) : (
        <div className="space-y-3 text-sm">
          <Row label="Original User Request" value={verdict.original_text} mono />
          <Row label="Parsed Banking Action" value={verdict.parsed.action?.replace(/_/g, " ") || "UNRESOLVED"} />
          <Row label="Parsed Amount" value={formatPaise(verdict.parsed.amount_paise)} />
          <Row label="Parsed Beneficiary" value={verdict.parsed.beneficiary || "UNRESOLVED"} />

          <div className={`rounded-lg border p-3 ${hasIntentMismatch ? "border-red-900 bg-red-950/20" : "border-slate-800 bg-slate-950/30"}`}>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Intent Consistency</div>
            {hasIntentMismatch ? (
              <div className="space-y-1">
                <div className="text-red-300 font-medium">MISMATCH DETECTED</div>
                {verdict.findings.filter(f => f.category === "INTENT_MISMATCH").map((f, i) => (
                  <div key={i} className="text-xs text-slate-400">
                    <span className="text-amber-300">{f.evidence}</span> — {f.explanation}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-green-300 text-xs">
                {verdict.status === "BLOCKED"
                  ? "No intent mismatch, but request blocked for other security reasons."
                  : verdict.status === "CONFIRMATION_REQUIRED"
                  ? "Intent is consistent. Transfer requires explicit confirmation."
                  : "Intent is consistent and safe."}
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Row label="Confirmation State" value={
              verdict.confirmation_id ? "PENDING — Token issued" :
              verdict.executed ? "CONFIRMED & EXECUTED" :
              "NOT REQUIRED"
            } />
            <Row label="Execution State" value={verdict.executed ? "EXECUTED" : "NOT EXECUTED"} />
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-2.5">
      <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className={`text-sm text-slate-200 mt-0.5 ${mono ? "font-mono text-xs break-words" : ""}`}>{value}</div>
    </div>
  );
}
