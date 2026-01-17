/**
 * FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
 * 
 * Offer API
 * 
 * Handles offer management with grace periods and controlled decisions.
 * All state is backend-authoritative. Frontend only sends intent and renders outcome.
 * 
 * BACKEND CONTRACT:
 * - GET  /api/offers           → Offer[]
 * - GET  /api/offers/pending   → Offer[]
 * - GET  /api/offers/:id       → Offer | null
 * - POST /api/offers/:id/accept  → OfferDecision
 * - POST /api/offers/:id/decline → OfferDecision
 */

import api from '@/utils/api';
import type { Offer, OfferDecision } from '@/types/aura';

// ============================================================================
// API FUNCTIONS — BACKEND-READY HTTP STUBS
// ============================================================================

/**
 * Fetches all offers for the current student.
 * Backend handles expiration logic — frontend does NOT compute status.
 */
export const getOffers = async (): Promise<Offer[]> => {
  const response = await api.get<Offer[]>('/api/offers');
  return response.data;
};

/**
 * Fetches only pending offers.
 * Backend filters by status — frontend renders what it receives.
 */
export const getPendingOffers = async (): Promise<Offer[]> => {
  const response = await api.get<Offer[]>('/api/offers/pending');
  return response.data;
};

/**
 * Fetches a specific offer by ID.
 */
export const getOfferById = async (offerId: string): Promise<Offer | null> => {
  try {
    const response = await api.get<Offer>(`/api/offers/${offerId}`);
    return response.data;
  } catch (error: unknown) {
    // 404 means offer not found
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
 * Accepts an offer.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates offer is still pending
 * - Backend validates grace period
 * - Backend supersedes other pending offers
 * - Backend handles atomicity
 * 
 * FRONTEND RESPONSIBILITY:
 * - Disable UI during request
 * - Handle 409 (conflict) / 400 (expired) gracefully
 * - Re-fetch offers after action
 */
export const acceptOffer = async (offerId: string): Promise<OfferDecision> => {
  const response = await api.post<OfferDecision>(`/api/offers/${offerId}/accept`);
  return response.data;
};

/**
 * Declines an offer.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates offer is still pending
 * - Backend records decision timestamp
 * 
 * FRONTEND RESPONSIBILITY:
 * - Disable UI during request
 * - Handle errors gracefully
 * - Re-fetch offers after action
 */
export const declineOffer = async (offerId: string): Promise<OfferDecision> => {
  const response = await api.post<OfferDecision>(`/api/offers/${offerId}/decline`);
  return response.data;
};

// ============================================================================
// UI HELPER — DISPLAY ONLY (NO BUSINESS LOGIC)
// ============================================================================

/**
 * Calculates remaining time for display purposes ONLY.
 * 
 * IMPORTANT: This is for UI countdown display only.
 * Backend is authoritative for actual expiration.
 * Frontend must NOT auto-expire offers based on this.
 * 
 * NOTE: Renamed from getGracePeriodRemaining for backward compatibility.
 */
export const getGracePeriodRemaining = (offer: Offer): {
  hours: number;
  minutes: number;
  expired: boolean;
  urgent: boolean;
} => {
  const now = new Date();
  const deadline = new Date(offer.decisionDeadline);
  const diffMs = deadline.getTime() - now.getTime();
  
  if (diffMs <= 0) {
    return { hours: 0, minutes: 0, expired: true, urgent: true };
  }
  
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  const urgent = hours < 12;
  
  return { hours, minutes, expired: false, urgent };
};
