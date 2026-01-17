/**
 * FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
 * 
 * Review API
 * 
 * Handles flag/review requests for match explainability.
 * All state is backend-authoritative. Frontend only sends intent and renders outcome.
 * 
 * BACKEND CONTRACT:
 * - GET  /api/reviews                    → ReviewRequest[]
 * - GET  /api/reviews/match/:matchId     → ReviewRequest | null
 * - GET  /api/reviews/can-request/:matchId → { canRequest: boolean }
 * - POST /api/reviews/flag               → ReviewRequest
 * - POST /api/reviews/manual             → ReviewRequest
 * - GET  /api/reviews/:reviewId          → ReviewRequest | null
 */

import api from '@/utils/api';
import type { ReviewRequest, FlagReason } from '@/types/aura';

// ============================================================================
// API FUNCTIONS — BACKEND-READY HTTP STUBS
// ============================================================================

/**
 * Fetches all review requests for the current user.
 */
export const getReviewRequests = async (): Promise<ReviewRequest[]> => {
  const response = await api.get<ReviewRequest[]>('/api/reviews');
  return response.data;
};

/**
 * Gets the review request for a specific match, if one exists.
 */
export const getReviewByMatchId = async (
  matchId: string
): Promise<ReviewRequest | null> => {
  try {
    const response = await api.get<ReviewRequest>(
      `/api/reviews/match/${matchId}`
    );
    return response.data;
  } catch (error: unknown) {
    // 404 means no review exists for this match
    if (error && typeof error === 'object' && 'response' in error) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        return null;
      }
    }
    throw error;
  }
};

/**
 * Checks if a review can be requested for a match.
 * 
 * BACKEND AUTHORITY:
 * - Backend enforces MAX_REVIEW_REQUESTS_PER_MATCH
 * - Backend checks if match exists and is eligible
 */
export const canRequestReview = async (matchId: string): Promise<boolean> => {
  const response = await api.get<{ canRequest: boolean }>(
    `/api/reviews/can-request/${matchId}`
  );
  return response.data.canRequest;
};

/**
 * Submits a flag request with a predefined reason.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates no existing review for match
 * - Backend creates review with submitted status
 * - Backend generates reviewId and timestamps
 * 
 * FRONTEND RESPONSIBILITY:
 * - Collect reason from user
 * - Disable UI during submission
 * - Handle 409 (already exists) gracefully
 */
export const submitFlagRequest = async (
  matchId: string,
  reason: FlagReason,
  otherReason: string | null
): Promise<ReviewRequest> => {
  const response = await api.post<ReviewRequest>('/api/reviews/flag', {
    matchId,
    reason,
    otherReason: reason === 'other' ? otherReason : null,
  });
  return response.data;
};

/**
 * Submits a manual review request with free-form reason.
 * 
 * Same backend contract as submitFlagRequest but allows
 * more detailed explanation.
 */
export const submitManualReviewRequest = async (
  matchId: string,
  reason: string
): Promise<ReviewRequest> => {
  const response = await api.post<ReviewRequest>('/api/reviews/manual', {
    matchId,
    reason,
  });
  return response.data;
};

/**
 * Gets the status of a specific review request.
 */
export const getReviewStatus = async (
  reviewId: string
): Promise<ReviewRequest | null> => {
  try {
    const response = await api.get<ReviewRequest>(
      `/api/reviews/${reviewId}`
    );
    return response.data;
  } catch (error: unknown) {
    // 404 means review not found
    if (error && typeof error === 'object' && 'response' in error) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        return null;
      }
    }
    throw error;
  }
};
