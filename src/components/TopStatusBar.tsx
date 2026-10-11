import { Shield, Activity, Lock, Zap } from "lucide-react";

interface Props {
  auditChainValid: boolean | null;
  firewallActive: boolean;
}

export function TopStatusBar({ auditChainValid, firewallActive }: Props) {
  return (
    <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
              <Shield className="w-6 h-6 text-slate-950" strokeWidth={2.5} />
            </div>
            <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-green-500 border-2 border-slate-950 flex items-center justify-center">
              <Lock className="w-2.5 h-2.5 text-slate-950" strokeWidth={3} />
            </div>
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">
              BankSim
            </h1>
            <p className="text-[10px] text-cyan-400 font-medium tracking-wider uppercase">
              Blue-Team AI Firewall
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
            <div className={`w-2 h-2 rounded-full ${firewallActive ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs font-medium text-slate-300">
              {firewallActive ? "FIREWALL ACTIVE" : "FIREWALL DOWN"}
            </span>
          </div>

          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-xs font-medium text-slate-300">DEMO MODE</span>
          </div>

          <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
            auditChainValid === null
              ? "bg-slate-900 border-slate-800"
              : auditChainValid
              ? "bg-green-950/50 border-green-800/50"
              : "bg-red-950/50 border-red-800/50"
          }`}>
            <Zap className={`w-3.5 h-3.5 ${
              auditChainValid === null ? "text-slate-500" : auditChainValid ? "text-green-400" : "text-red-400"
            }`} />
            <span className={`text-xs font-medium ${
              auditChainValid === null ? "text-slate-400" : auditChainValid ? "text-green-300" : "text-red-300"
            }`}>
              {auditChainValid === null ? "CHAIN: NOT CHECKED" : auditChainValid ? "CHAIN: VALID" : "CHAIN: FAIL"}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
