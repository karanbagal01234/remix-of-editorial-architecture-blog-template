// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * User Service - Minimal utility functions
 * 
 * NOTE: This file no longer contains localStorage persistence for domain data.
 * All user data is fetched from backend APIs.
 * Only onboarding state (UI preference) is stored locally.
 */

import type { UserData, MatchResult, UserPreferences, UserLocation } from '@/types/student';

// Re-export types for convenience
export type { UserData, MatchResult, UserPreferences, UserLocation };

const ONBOARDING_KEY = 'aura_onboarding_complete';

/**
 * Get onboarding status - UI preference only
 */
export const getOnboardingStatus = (): boolean => {
  return localStorage.getItem(ONBOARDING_KEY) === 'true';
};

/**
 * Set onboarding complete - UI preference only
 */
export const setOnboardingComplete = (): void => {
  localStorage.setItem(ONBOARDING_KEY, 'true');
};

/**
 * Clear onboarding status
 */
export const clearOnboardingStatus = (): void => {
  localStorage.removeItem(ONBOARDING_KEY);
};

/**
 * Check if user is fully verified
 * Based on backend response - NOT computed locally
 */
export const isFullyVerified = (user: UserData | null): boolean => {
  if (!user) return false;
  return user.emailVerified && user.phoneVerified;
};

/**
 * Check if profile is complete
 * Based on required fields - validated by backend
 */
export const isProfileComplete = (user: UserData | null): boolean => {
  if (!user) return false;
  return !!(user.name && user.email && user.phone && user.location);
};

/**
 * Get verification status from user data
 * All status comes from backend
 */
export const getVerificationStatus = (user: UserData | null): { 
  email: boolean; 
  phone: boolean; 
  fullyVerified: boolean;
  nextStep: string | null;
} => {
  if (!user) {
    return { email: false, phone: false, fullyVerified: false, nextStep: '/login' };
  }
  
  const fullyVerified = user.emailVerified && user.phoneVerified;
  
  let nextStep: string | null = null;
  if (!fullyVerified) {
    if (!user.emailVerified) {
      nextStep = '/verify/email';
    } else if (!user.phoneVerified) {
      nextStep = '/verify/phone';
    }
  }
  
  return {
    email: user.emailVerified,
    phone: user.phoneVerified,
    fullyVerified,
    nextStep,
  };
};
