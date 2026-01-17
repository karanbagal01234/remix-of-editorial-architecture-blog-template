// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Matching Engine API - Backend-ready stubs
 * 
 * ═══════════════════════════════════════════════════════════════
 * OWNERSHIP: SYSTEM-ONLY
 * ═══════════════════════════════════════════════════════════════
 * 
 * CORE PRINCIPLE: Companies DO NOT browse candidates.
 * The SYSTEM computes matches. Companies only VALIDATE.
 * 
 * All matching logic is BACKEND-OWNED.
 * Frontend only sends intent and displays results.
 * 
 * NO localStorage. NO local computation.
 */

import api from '@/utils/api';
import type { 
  MatchProposal, 
  MatchAction, 
  JobMatchSummary,
} from '@/types/match';

// ═══════════════════════════════════════════════════════════════
// PUBLIC API - All backend-driven
// ═══════════════════════════════════════════════════════════════

/**
 * RUN MATCHING - SYSTEM ACTION
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 * Backend computes all match proposals.
 */
export const runMatching = async (jobId: string): Promise<MatchProposal[]> => {
  const response = await api.post<MatchProposal[]>(`/company/jobs/${jobId}/match`);
  return response.data;
};

/**
 * GET MATCHES FOR JOB - READ-ONLY
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const getMatchesForJob = async (jobId: string): Promise<MatchProposal[]> => {
  const response = await api.get<MatchProposal[]>(`/company/jobs/${jobId}/matches`);
  return response.data;
};

/**
 * PERFORM MATCH ACTION - COMPANY INTENT
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 * Company can only approve/reject/hold. Cannot edit scores.
 */
export const performMatchAction = async (matchId: string, action: MatchAction): Promise<MatchProposal> => {
  const response = await api.post<MatchProposal>(`/company/matches/${matchId}/action`, { action });
  return response.data;
};

/**
 * GET JOB MATCH SUMMARY - READ-ONLY
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const getJobMatchSummary = async (jobId: string, intake: number): Promise<JobMatchSummary> => {
  const response = await api.get<JobMatchSummary>(`/company/jobs/${jobId}/summary`, {
    params: { intake }
  });
  return response.data;
};

/**
 * GET SINGLE MATCH - READ-ONLY
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const getMatchById = async (matchId: string): Promise<MatchProposal | null> => {
  try {
    const response = await api.get<MatchProposal>(`/company/matches/${matchId}`);
    return response.data;
  } catch {
    return null;
  }
};
