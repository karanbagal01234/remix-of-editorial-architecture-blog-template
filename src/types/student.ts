// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// Single source of truth for all student-related types

export type UserStatus = 
  | 'profile-pending' 
  | 'skills-pending' 
  | 'preferences-pending' 
  | 'submitted' 
  | 'processing' 
  | 'matched' 
  | 'waitlist' 
  | 'rejected' 
  | 'confirmed' 
  | 'seeking-alternative';

export type MatchResultStatus = 'matched' | 'waitlist' | 'rejected';

export interface MatchResult {
  companyId: string;
  companyName: string;
  score: number;
  explanation: string[];
  status: MatchResultStatus;
}

export interface UserPreferences {
  domains: string[];
  workStyle: 'remote' | 'hybrid' | 'onsite';
  distance: number;
  stipend: number | null;
}

export interface UserLocation {
  lat: number;
  lng: number;
}

/**
 * UserData - Backend-authoritative user profile
 * IMPORTANT: All fields are READ-ONLY from frontend perspective
 * Frontend MUST NOT compute or derive values - always fetch from backend
 */
export interface UserData {
  id: string;
  name: string;
  email: string;
  phone: string;
  location: UserLocation | null;
  skills: string[];
  resume: string | null;
  preferences: UserPreferences | null;
  status: UserStatus;
  /** Email verified via OTP */
  emailVerified: boolean;
  /** Phone verified via OTP */
  phoneVerified: boolean;
  token: string | null;
  matchResult: MatchResult | null;
  onboardingComplete: boolean;
  createdAt: string;
}

// Flow step definitions
export type FlowStep = 
  | 'profile'
  | 'skills'
  | 'preferences'
  | 'status'
  | 'result';

export interface FlowRequirement {
  requireFullVerification: boolean;
  requireProfile: boolean;
  requireSkills: boolean;
  requirePreferences: boolean;
  requireMatchResult: boolean;
}
