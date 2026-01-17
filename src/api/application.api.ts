/**
 * FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
 * 
 * Application API
 * 
 * Handles application lifecycle, withdrawal, and cooldowns.
 * All state is backend-authoritative. Frontend only sends intent and renders outcome.
 * 
 * BACKEND CONTRACT:
 * - GET  /api/application/state      → ApplicationState
 * - GET  /api/application/can-withdraw → { canWithdraw: boolean; reason: string | null }
 * - POST /api/application/withdraw   → ApplicationState
 * - POST /api/application/reapply    → ApplicationState
 */

import api from '@/utils/api';
import type { ApplicationState } from '@/types/aura';

// ============================================================================
// API FUNCTIONS — BACKEND-READY HTTP STUBS
// ============================================================================

/**
 * Fetches the current application state.
 * 
 * BACKEND AUTHORITY:
 * - Backend computes current status (active, withdrawn, cooldown, completed)
 * - Backend handles cooldown expiration logic
 * - Frontend renders what backend provides
 */
export const getApplicationState = async (): Promise<ApplicationState> => {
  const response = await api.get<ApplicationState>('/api/application/state');
  return response.data;
};

/**
 * Checks if the current application can be withdrawn.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates current state
 * - Backend checks for accepted offers
 * - Backend enforces business rules
 */
export const canWithdrawApplication = async (): Promise<{
  canWithdraw: boolean;
  reason: string | null;
}> => {
  const response = await api.get<{
    canWithdraw: boolean;
    reason: string | null;
  }>('/api/application/can-withdraw');
  return response.data;
};

/**
 * Withdraws the current application.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates withdrawal is allowed
 * - Backend sets cooldown period
 * - Backend records withdrawal reason and timestamp
 * 
 * FRONTEND RESPONSIBILITY:
 * - Confirm withdrawal with user
 * - Send reason to backend
 * - Handle 400/409 errors gracefully
 */
export const withdrawApplication = async (
  reason: string
): Promise<ApplicationState> => {
  const response = await api.post<ApplicationState>(
    '/api/application/withdraw',
    { reason }
  );
  return response.data;
};

/**
 * Reapplies after cooldown period has ended.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates cooldown has expired
 * - Backend resets application state to active
 * - Backend returns 400 if cooldown not complete
 */
export const reapply = async (): Promise<ApplicationState> => {
  const response = await api.post<ApplicationState>(
    '/api/application/reapply'
  );
  return response.data;
};

// ============================================================================
// UI HELPER — DISPLAY ONLY (NO BUSINESS LOGIC)
// ============================================================================

/**
 * Calculates remaining cooldown time for display purposes ONLY.
 * 
 * IMPORTANT: This is for UI display only.
 * Backend is authoritative for actual cooldown status.
 * Frontend must NOT auto-transition states based on this.
 * 
 * NOTE: Kept original function name for backward compatibility.
 */
export const getCooldownRemaining = (state: ApplicationState): {
  days: number;
  hours: number;
  canReapply: boolean;
} => {
  if (!state.cooldownEndsAt || state.status !== 'cooldown') {
    return { days: 0, hours: 0, canReapply: true };
  }
  
  const now = new Date();
  const cooldownEnd = new Date(state.cooldownEndsAt);
  const diffMs = cooldownEnd.getTime() - now.getTime();
  
  if (diffMs <= 0) {
    return { days: 0, hours: 0, canReapply: true };
  }
  
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  return { days, hours, canReapply: false };
};
