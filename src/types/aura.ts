// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Aura-Match Core Types
 * 
 * SYSTEM-OWNED ENTITIES
 * These types represent the core business entities of the matching platform.
 * All entities are immutable after terminal states.
 */

// ============================================================================
// RESUME VERSIONING
// ============================================================================

export type ResumeStatus = 'active' | 'archived' | 'pending_extraction';

export interface ResumeVersion {
  readonly resumeId: string;
  readonly version: number;
  readonly fileName: string;
  readonly uploadedAt: string;
  readonly status: ResumeStatus;
  readonly extractedSkills: string[];
  readonly skillsConfirmed: boolean;
  readonly fileSize: number; // in bytes
}

export interface ResumeHistory {
  readonly currentVersion: ResumeVersion | null;
  readonly archivedVersions: ResumeVersion[];
}

// ============================================================================
// OFFER SYSTEM
// ============================================================================

export type OfferStatus = 
  | 'pending'      // Awaiting student decision
  | 'accepted'     // Student accepted
  | 'declined'     // Student declined
  | 'expired'      // Grace period elapsed
  | 'withdrawn'    // System withdrew (e.g., position filled)
  | 'superseded';  // Another offer was accepted, this was auto-expired

export interface Offer {
  readonly offerId: string;
  readonly matchId: string;
  readonly jobId: string;
  readonly companyId: string;
  readonly companyName: string;
  readonly roleTitle: string;
  readonly location: string;
  readonly matchScore: number;
  readonly status: OfferStatus;
  readonly createdAt: string;
  readonly decisionDeadline: string; // ISO date - grace period end
  readonly decidedAt: string | null;
  readonly resumeVersionUsed: number;
  readonly explanation: string[];
  readonly systemNote: string | null;
}

export interface OfferDecision {
  offerId: string;
  action: 'accept' | 'decline';
  timestamp: string;
}

// ============================================================================
// REVIEW & FLAG SYSTEM
// ============================================================================

export type FlagReason = 
  | 'skills_misinterpreted'
  | 'resume_context_ignored'
  | 'domain_mismatch'
  | 'location_logic_incorrect'
  | 'other';

export type ReviewStatus = 
  | 'submitted'
  | 'under_review'
  | 'resolved';

export interface ReviewRequest {
  readonly reviewId: string;
  readonly matchId: string;
  readonly reason: FlagReason;
  readonly otherReason: string | null; // Only if reason === 'other'
  readonly createdAt: string;
  readonly status: ReviewStatus;
  readonly resolvedAt: string | null;
  readonly resolution: string | null; // System response after resolution
}

export const FLAG_REASON_LABELS: Record<FlagReason, string> = {
  skills_misinterpreted: 'Skills misinterpreted',
  resume_context_ignored: 'Resume context ignored',
  domain_mismatch: 'Domain mismatch',
  location_logic_incorrect: 'Location logic incorrect',
  other: 'Other',
};

// ============================================================================
// APPLICATION LIFECYCLE
// ============================================================================

export type ApplicationStatus = 
  | 'active'
  | 'withdrawn'
  | 'cooldown'
  | 'completed';

export interface ApplicationState {
  readonly status: ApplicationStatus;
  readonly withdrawnAt: string | null;
  readonly cooldownEndsAt: string | null;
  readonly cooldownDays: number;
  readonly canReapply: boolean;
  readonly withdrawalReason: string | null;
}

// ============================================================================
// PRIVACY STATES
// ============================================================================

export interface PrivacyState {
  readonly contactVisible: boolean;
  readonly exactLocationVisible: boolean;
  readonly fullResumeVisible: boolean;
  readonly mutualAcceptance: boolean;
}

// ============================================================================
// STUDENT FLOW STATE (AGGREGATED)
// ============================================================================

export interface StudentFlowState {
  readonly resumeHistory: ResumeHistory;
  readonly offers: Offer[];
  readonly reviewRequests: ReviewRequest[];
  readonly applicationState: ApplicationState;
  readonly privacyState: PrivacyState;
}

// ============================================================================
// CONFIGURATION (SYSTEM-OWNED)
// ============================================================================

export const SYSTEM_CONFIG = {
  GRACE_PERIOD_HOURS: 72,
  COOLDOWN_DAYS: 30,
  LOW_SCORE_THRESHOLD: 50,
  MAX_REVIEW_REQUESTS_PER_MATCH: 1,
} as const;
