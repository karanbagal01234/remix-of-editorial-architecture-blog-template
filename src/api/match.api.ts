// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Match API - Backend-ready stubs
 * 
 * OWNERSHIP: SYSTEM
 * Frontend only displays backend-provided match data.
 * NO localStorage. NO local computation.
 */

import api from '@/utils/api';
import type { MatchResult } from '@/types/student';

/**
 * Run match simulation - SYSTEM ACTION
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 * Backend computes all matches. Frontend only triggers and displays.
 */
export const runMatchSimulation = async (): Promise<MatchResult> => {
  const response = await api.post<MatchResult>('/student/match/run');
  return response.data;
};

/**
 * Get current match status
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const getMatchStatus = async (): Promise<MatchResult | null> => {
  const response = await api.get<MatchResult | null>('/student/match/status');
  return response.data;
};

/**
 * Accept match offer
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const acceptMatch = async (): Promise<boolean> => {
  const response = await api.post<{ success: boolean }>('/student/match/accept');
  return response.data.success;
};

/**
 * Decline match offer
 * 
 * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
 */
export const declineMatch = async (): Promise<boolean> => {
  const response = await api.post<{ success: boolean }>('/student/match/decline');
  return response.data.success;
};
