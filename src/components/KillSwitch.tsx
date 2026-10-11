import { Shield, ShieldCheck, ShieldAlert, Ban, AlertTriangle, CheckCircle2 } from "lucide-react";
import type { SecurityVerdict } from "../types";

interface Props {
  verdict: SecurityVerdict | null;
}

export function KillSwitch({ verdict }: Props) {
  const status = verdict?.status || "IDLE";

  const config = {
    IDLE: { icon: Shield, color: "text-cyan-400", bg: "bg-slate-900 border-slate-700", label: "FIREWALL ACTIVE", desc: "Awaiting request..." },
    APPROVED: { icon: CheckCircle2, color: "text-green-400", bg: "bg-green-950/30 border-green-800", label: "SAFE REQUEST", desc: "Request approved by the firewall" },
    BLOCKED: { icon: Ban, color: "text-red-400", bg: "bg-red-950/30 border-red-800", label: "ATTACK DETECTED — TRANSACTION BLOCKED", desc: "Malicious or invalid request stopped" },
    CONFIRMATION_REQUIRED: { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-950/30 border-amber-800", label: "CONFIRMATION REQUIRED", desc: "Transfer needs explicit user confirmation" },
    REVIEW: { icon: ShieldAlert, color: "text-amber-400", bg: "bg-amber-950/30 border-amber-800", label: "SECURITY REVIEW", desc: "Request flagged for review" },
  } as const;

  const c = config[status as keyof typeof config] || config.IDLE;
  const Icon = c.icon;

  const formatPaise = (p: number | null) => p !== null ? `₹${(p / 100).toLocaleString("en-IN", { minimumFractionDigits: 2 })}` : "—";
  const moneyProtected = verdict?.status === "BLOCKED" && verdict.amount_paise && verdict.amount_paise > 0
    ? formatPaise(verdict.amount_paise)
    : null;

  return (
    <div className={`card border-2 p-5 transition-all duration-300 ${c.bg} ${verdict?.status === "BLOCKED" ? "pulse-glow" : ""}`}>
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">Transaction Kill Switch</h2>
      </div>

      <div className="flex items-center gap-4 mb-4">
        <div className={`w-16 h-16 rounded-xl bg-slate-950/50 flex items-center justify-center ${c.color}`}>
          <Icon className="w-8 h-8" />
        </div>
        <div>
          <div className={`text-lg font-bold ${c.color}`}>{c.label}</div>
          <div className="text-xs text-slate-400">{c.desc}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        <InfoRow label="Attempted Action" value={verdict?.action?.replace(/_/g, " ") || "—"} />
        <InfoRow label="Threat Category" value={verdict?.threat_category || "NONE"} />
        <InfoRow label="Attempted Amount" value={formatPaise(verdict?.amount_paise ?? null)} />
        <InfoRow label="Target Account" value={verdict?.beneficiary || "—"} />
        <InfoRow label="Execution Status" value={verdict?.executed ? "EXECUTED" : "NOT EXECUTED"} />
        <InfoRow label="Actual Transfer" value={formatPaise(verdict?.actual_amount_transferred_paise ?? 0)} />
        {moneyProtected && (
          <div className="col-span-2 mt-2 p-3 rounded-lg bg-green-950/40 border border-green-800/50">
            <div className="text-xs text-green-400 font-semibold uppercase tracking-wider">Fictional Funds Protected</div>
            <div className="text-2xl font-bold text-green-300 mt-1">{moneyProtected}</div>
          </div>
        )}
        {verdict?.confirmation_id && (
          <div className="col-span-2 mt-2 p-3 rounded-lg bg-amber-950/40 border border-amber-800/50">
            <div className="text-xs text-amber-400 font-semibold uppercase tracking-wider">Confirmation Required</div>
            <div className="text-xs text-amber-200 mt-1 font-mono break-all">{verdict.confirmation_id}</div>
          </div>
        )}
      </div>

      {!verdict && (
        <div className="text-center py-6 text-slate-500 text-sm">
          Submit a request to see the kill switch in action.
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-2.5 rounded-lg bg-slate-950/30 border border-slate-800/50">
      <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className="text-sm text-slate-200 font-medium mt-0.5 truncate">{value}</div>
    </div>
  );
}
