import { useState, useEffect } from "react";
import { ScrollText, ShieldCheck, ShieldAlert, Loader2, FlaskConical } from "lucide-react";
import { api } from "../api";
import type { AuditEvent, ChainVerification, TamperDemoResult } from "../types";

export function SecurityLedger() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [verification, setVerification] = useState<ChainVerification | null>(null);
  const [tamperResult, setTamperResult] = useState<TamperDemoResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [tampering, setTampering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadEvents() {
    setLoading(true);
    try {
      const { events } = await api.getAuditEvents();
      setEvents(events);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load events");
    } finally {
      setLoading(false);
    }
  }

  async function verifyChain() {
    setVerifying(true);
    try {
      const r = await api.verifyChain();
      setVerification(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  }

  async function tamperDemo() {
    setTampering(true);
    try {
      const r = await api.tamperDemo();
      setTamperResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Tamper demo failed");
    } finally {
      setTampering(false);
    }
  }

  useEffect(() => {
    loadEvents();
  }, []);

  return (
    <div className="card p-5 slide-up">
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <ScrollText className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">Tamper-Evident Security Ledger</h2>
        <span className="text-[10px] text-slate-500 uppercase tracking-wider">SHA-256 hash chain</span>
      </div>

      <div className="flex gap-2 mb-4 flex-wrap">
        <button className="btn btn-ghost flex items-center gap-2" onClick={loadEvents} disabled={loading}>
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ScrollText className="w-4 h-4" />}
          Refresh Events
        </button>
        <button className="btn btn-primary flex items-center gap-2" onClick={verifyChain} disabled={verifying}>
          {verifying ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
          Verify Chain
        </button>
        <button className="btn btn-ghost flex items-center gap-2" onClick={tamperDemo} disabled={tampering}>
          {tampering ? <Loader2 className="w-4 h-4 animate-spin" /> : <FlaskConical className="w-4 h-4" />}
          Tamper Demo
        </button>
      </div>

      {error && <p className="text-sm text-red-400 mb-3">{error}</p>}

      {verification && (
        <div className={`rounded-lg border p-3 mb-4 ${
          verification.valid ? "border-green-800 bg-green-950/20" : "border-red-800 bg-red-950/20"
        }`}>
          <div className="flex items-center gap-2">
            {verification.valid ? (
              <><ShieldCheck className="w-5 h-5 text-green-400" /><span className="text-green-300 font-semibold">VALID CHAIN</span></>
            ) : (
              <><ShieldAlert className="w-5 h-5 text-red-400" /><span className="text-red-300 font-semibold">INTEGRITY FAILURE</span></>
            )}
            <span className="text-xs text-slate-400 ml-auto">{verification.total_events} events</span>
          </div>
          {verification.errors.length > 0 && (
            <div className="mt-2 space-y-1">
              {verification.errors.slice(0, 5).map((e, i) => (
                <div key={i} className="text-xs text-red-300">{e}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {tamperResult && (
        <div className="rounded-lg border border-slate-700 bg-slate-950/40 p-3 mb-4 text-xs">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Safe Tampering Demonstration (separate copy)</div>
          <div className="space-y-1.5">
            <div>
              <span className="text-slate-500">Original chain:</span>{" "}
              <span className={tamperResult.original_valid ? "text-green-300" : "text-red-300"}>
                {tamperResult.original_valid ? "VALID" : "FAILED"}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Tampered chain:</span>{" "}
              <span className={tamperResult.tampered_valid ? "text-green-300" : "text-red-300"}>
                {tamperResult.tampered_valid ? "VALID" : "INTEGRITY FAILURE DETECTED"}
              </span>
            </div>
            <div className="text-slate-400 mt-1">{tamperResult.tampered_event}</div>
            {tamperResult.tampered_errors.length > 0 && (
              <div className="text-red-300 mt-1">{tamperResult.tampered_errors[0]}</div>
            )}
            <div className="text-slate-500 italic mt-1 text-[11px]">
              The main audit history was not modified. This demonstration uses an in-memory copy.
            </div>
          </div>
        </div>
      )}

      <div className="max-h-[400px] overflow-y-auto space-y-1.5 pr-1">
        {events.length === 0 ? (
          <div className="text-center py-6 text-slate-500 text-sm">No audit events recorded yet.</div>
        ) : (
          events.map((e, i) => (
            <div key={e.id} className="rounded-lg bg-slate-950/40 border border-slate-800 p-2.5 text-xs">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className={`badge text-[10px] ${
                  e.verdict === "BLOCKED" ? "bg-red-950 text-red-300" :
                  e.verdict === "APPROVED" ? "bg-green-950 text-green-300" :
                  "bg-amber-950 text-amber-300"
                }`}>{e.verdict}</span>
                {e.threat_category && e.threat_category !== "NONE" && (
                  <span className="text-[10px] text-amber-400">{e.threat_category}</span>
                )}
                <span className="text-slate-600 text-[10px] ml-auto">{new Date(e.event_timestamp).toLocaleTimeString()}</span>
              </div>
              {e.sanitized_request && (
                <div className="text-slate-400 text-[11px] truncate">{e.sanitized_request}</div>
              )}
              <div className="flex items-center gap-1 mt-1 text-[10px] text-slate-600 font-mono">
                <span>prev: {e.previous_hash.slice(0, 12)}...</span>
                <span>curr: {e.current_hash.slice(0, 12)}...</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
