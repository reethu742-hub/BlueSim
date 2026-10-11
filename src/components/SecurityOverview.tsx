import { ShieldCheck, ShieldAlert, Ban, TrendingUp, ClipboardCheck } from "lucide-react";
import type { DashboardStats } from "../types";

interface Props {
  stats: DashboardStats | null;
}

function StatCard({
  icon,
  label,
  value,
  sublabel,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sublabel?: string;
  color: string;
}) {
  return (
    <div className="card p-4 hover:border-slate-700 transition-colors slide-up">
      <div className="flex items-start justify-between mb-2">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
          {icon}
        </div>
      </div>
      <div className="stat-value text-white">{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
      {sublabel && <div className="text-[10px] text-slate-500 mt-0.5">{sublabel}</div>}
    </div>
  );
}

export function SecurityOverview({ stats }: Props) {
  const passRate = stats?.test_pass_rate;
  const passRateDisplay = passRate === null || passRate === undefined ? "Not tested" : `${passRate.toFixed(1)}%`;

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
      <StatCard
        icon={<ShieldCheck className="w-5 h-5 text-cyan-400" />}
        label="Requests Inspected"
        value={stats?.requests_inspected ?? "—"}
        color="bg-cyan-950/40"
      />
      <StatCard
        icon={<ShieldAlert className="w-5 h-5 text-amber-400" />}
        label="Threats Detected"
        value={stats?.threats_detected ?? "—"}
        color="bg-amber-950/40"
      />
      <StatCard
        icon={<Ban className="w-5 h-5 text-red-400" />}
        label="Transactions Blocked"
        value={stats?.transactions_blocked ?? "—"}
        color="bg-red-950/40"
      />
      <StatCard
        icon={<TrendingUp className="w-5 h-5 text-green-400" />}
        label="Fictional Money Protected"
        value={stats?.fictional_money_protected_display ?? "₹0.00"}
        sublabel="Counterfactual estimate"
        color="bg-green-950/40"
      />
      <StatCard
        icon={<ClipboardCheck className="w-5 h-5 text-cyan-400" />}
        label="Demo Test-Suite Pass Rate"
        value={passRateDisplay}
        sublabel={`${stats?.test_passed ?? 0}/${stats?.test_total ?? 0} tests passed`}
        color="bg-cyan-950/40"
      />
    </div>
  );
}
