import { Stethoscope } from "lucide-react";
import type { SecurityVerdict } from "../types";

interface Props {
  verdict: SecurityVerdict | null;
}

export function AttackAutopsy({ verdict }: Props) {
  if (!verdict) {
    return (
      <div className="card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Stethoscope className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-white">AI Attack Autopsy</h2>
        </div>
        <div className="text-center py-6 text-slate-500 text-sm">
          Submit a request to see the forensic autopsy.
        </div>
      </div>
    );
  }

  const formatPaise = (p: number | null) => p !== null ? `₹${(p / 100).toLocaleString("en-IN", { minimumFractionDigits: 2 })}` : "UNRESOLVED";

  return (
    <div className="card p-5 slide-up">
      <div className="flex items-center gap-2 mb-4">
        <Stethoscope className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">AI Attack Autopsy</h2>
        <span className="text-[10px] text-slate-500 ml-auto">Rule-based analysis</span>
      </div>

      <div className="space-y-3 text-sm">
        {/* Original Request */}
        <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-3">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Submitted Request</div>
          <div className="text-slate-200 text-xs break-words">{verdict.original_text}</div>
        </div>

        {/* Normalized Text (if different) */}
        {verdict.normalized_text !== verdict.original_text && (
          <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-3">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Normalized Inspection Text</div>
            <div className="text-slate-300 text-xs break-words">{verdict.normalized_text}</div>
          </div>
        )}

        {/* Findings */}
        {verdict.findings.length > 0 ? (
          <div className="space-y-2">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Evidence & Detection</div>
            {verdict.findings.map((f, i) => (
              <div key={i} className="rounded-lg bg-red-950/20 border border-red-900/50 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="badge bg-red-950 text-red-300 border border-red-900 text-[10px]">
                    {f.category}
                  </span>
                </div>
                <div className="text-xs space-y-1">
                  <div><span className="text-slate-500">Suspicious phrase:</span> <span className="text-amber-300 font-mono">{f.evidence}</span></div>
                  <div><span className="text-slate-500">Matched rule:</span> <span className="text-slate-300">{f.rule}</span></div>
                  <div><span className="text-slate-500">Violated policy:</span> <span className="text-slate-300">{f.explanation}</span></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-lg bg-green-950/20 border border-green-900/50 p-3">
            <div className="text-xs text-green-300">No threat patterns detected in this request.</div>
          </div>
        )}

        {/* Parsed Transaction Details */}
        <div className="grid grid-cols-3 gap-2">
          <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-2.5">
            <div className="text-[10px] text-slate-500 uppercase">Parsed Action</div>
            <div className="text-sm text-slate-200">{verdict.parsed.action?.replace(/_/g, " ") || "UNRESOLVED"}</div>
          </div>
          <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-2.5">
            <div className="text-[10px] text-slate-500 uppercase">Parsed Amount</div>
            <div className="text-sm text-slate-200">{formatPaise(verdict.parsed.amount_paise)}</div>
          </div>
          <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-2.5">
            <div className="text-[10px] text-slate-500 uppercase">Parsed Beneficiary</div>
            <div className="text-sm text-slate-200">{verdict.parsed.beneficiary || "UNRESOLVED"}</div>
          </div>
        </div>

        {/* Final Verdict */}
        <div className={`rounded-lg border p-3 ${
          verdict.status === "BLOCKED" ? "bg-red-950/20 border-red-900" : "bg-slate-950/50 border-slate-800"
        }`}>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-slate-500">Final Verdict:</span>{" "}
              <span className={`font-bold ${verdict.status === "BLOCKED" ? "text-red-300" : "text-slate-200"}`}>{verdict.status}</span>
            </div>
            <div>
              <span className="text-slate-500">Execution:</span>{" "}
              <span className={verdict.executed ? "text-green-300" : "text-slate-300"}>{verdict.executed ? "Executed" : "Not executed"}</span>
            </div>
            <div>
              <span className="text-slate-500">Actual Transfer:</span>{" "}
              <span className="text-slate-200">{formatPaise(verdict.actual_amount_transferred_paise)}</span>
            </div>
            <div>
              <span className="text-slate-500">Balances Changed:</span>{" "}
              <span className={verdict.balances_changed ? "text-amber-300" : "text-green-300"}>{verdict.balances_changed ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>

        {/* Recommended Action */}
        <div className="rounded-lg bg-cyan-950/20 border border-cyan-900/50 p-3">
          <div className="text-[10px] text-cyan-400 uppercase tracking-wider mb-1">Recommended Safe Next Action</div>
          <div className="text-xs text-slate-300">
            {verdict.status === "BLOCKED"
              ? "Do not proceed with this request. Review the detected threat patterns and submit a corrected, legitimate banking request."
              : verdict.status === "CONFIRMATION_REQUIRED"
              ? "Review the transfer details carefully. Use the confirmation token to explicitly authorize the transfer if you intend to proceed."
              : "Request is safe. You may proceed with the banking action."}
          </div>
        </div>
      </div>
    </div>
  );
}
