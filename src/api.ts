import type {
  SecurityVerdict,
  Account,
  Transaction,
  AuditEvent,
  ArenaScenario,
  ArenaResult,
  ArenaAllResults,
  DashboardStats,
  BlastRadiusResult,
  ChainVerification,
  TamperDemoResult,
} from "./types";

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;
const BASE_URL = `${SUPABASE_URL}/functions/v1/banksim`;

const headers = {
  Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
  "Content-Type": "application/json",
};

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: `Request failed (${res.status})` }));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  const data = await res.json();
  if (data.error) {
    throw new Error(data.error);
  }
  return data as T;
}

export const api = {
  async health(): Promise<{ status: string }> {
    const res = await fetch(`${BASE_URL}/health`, { headers });
    return handleResponse(res);
  },

  async analyse(text: string, confirmationId?: string): Promise<SecurityVerdict> {
    const res = await fetch(`${BASE_URL}/analyse`, {
      method: "POST",
      headers,
      body: JSON.stringify({ text, confirmation_id: confirmationId || null }),
    });
    return handleResponse(res);
  },

  async getAccounts(): Promise<{ accounts: Account[] }> {
    const res = await fetch(`${BASE_URL}/accounts`, { headers });
    return handleResponse(res);
  },

  async getTransactions(): Promise<{ transactions: Transaction[] }> {
    const res = await fetch(`${BASE_URL}/transactions`, { headers });
    return handleResponse(res);
  },

  async blastRadius(text: string): Promise<BlastRadiusResult> {
    const res = await fetch(`${BASE_URL}/blast-radius`, {
      method: "POST",
      headers,
      body: JSON.stringify({ text }),
    });
    return handleResponse(res);
  },

  async getScenarios(): Promise<{ scenarios: ArenaScenario[] }> {
    const res = await fetch(`${BASE_URL}/arena/scenarios`, { headers });
    return handleResponse(res);
  },

  async runScenario(scenarioId: string): Promise<ArenaResult> {
    const res = await fetch(`${BASE_URL}/arena/run`, {
      method: "POST",
      headers,
      body: JSON.stringify({ scenario_id: scenarioId }),
    });
    return handleResponse(res);
  },

  async runAllScenarios(): Promise<ArenaAllResults> {
    const res = await fetch(`${BASE_URL}/arena/run-all`, {
      method: "POST",
      headers,
    });
    return handleResponse(res);
  },

  async getAuditEvents(): Promise<{ events: AuditEvent[] }> {
    const res = await fetch(`${BASE_URL}/audit/events`, { headers });
    return handleResponse(res);
  },

  async verifyChain(): Promise<ChainVerification> {
    const res = await fetch(`${BASE_URL}/audit/verify`, { headers });
    return handleResponse(res);
  },

  async tamperDemo(): Promise<TamperDemoResult> {
    const res = await fetch(`${BASE_URL}/audit/tamper-demo`, { headers });
    return handleResponse(res);
  },

  async getStats(): Promise<DashboardStats> {
    const res = await fetch(`${BASE_URL}/stats`, { headers });
    return handleResponse(res);
  },

  async resetDemo(): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${BASE_URL}/reset`, {
      method: "POST",
      headers,
    });
    return handleResponse(res);
  },

  async resetTests(): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${BASE_URL}/reset-tests`, {
      method: "POST",
      headers,
    });
    return handleResponse(res);
  },
};
