// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Match Types - System-owned matching engine models
 * 
 * ═══════════════════════════════════════════════════════════════
 * OWNERSHIP: SYSTEM-ONLY
 * ═══════════════════════════════════════════════════════════════
 * 
 * IMPORTANT: Companies DO NOT control matching.
 * All match data is SYSTEM-GENERATED and IMMUTABLE.
 * Companies can only validate (approve/reject/hold).
 * 
 * RULES:
 * - MatchProposal is append-only after generation
 * - Scores are NEVER editable by any UI
 * - Explanations are NEVER editable by any UI
 * - Status transitions are RESTRICTED (see VALID_TRANSITIONS)
 * - UI components MUST treat all fields as read-only
 * 
 * BACKEND COMPATIBILITY:
 * - All types are designed to be replaced by API responses
 * - No UI logic should depend on local computation
 * - Storage access is centralized in matchingEngine.api.ts
 */

// ═══════════════════════════════════════════════════════════════
// STATUS & TRANSITIONS (SYSTEM-CONTROLLED)
// ═══════════════════════════════════════════════════════════════

/** Status of a match proposal - system-owned state */
export type MatchProposalStatus = 'pending' | 'approved' | 'rejected' | 'hold' | 'locked';

/**
 * Valid status transitions - ENFORCED by matching engine
 * pending → approved | rejected | hold | locked (via intake full)
 * hold → approved | rejected | locked (via intake full)
 * approved → (terminal)
 * rejected → (terminal)
 * locked → (terminal)
 */
export const VALID_STATUS_TRANSITIONS: Record<MatchProposalStatus, readonly MatchProposalStatus[]> = {
  pending: ['approved', 'rejected', 'hold', 'locked'] as const,
  hold: ['approved', 'rejected', 'locked'] as const,
  approved: [] as const, // Terminal
  rejected: [] as const, // Terminal
  locked: [] as const,   // Terminal
} as const;

/**
 * Check if a status transition is valid
 * SYSTEM USE ONLY - UI should not perform transitions
 */
export const isValidTransition = (from: MatchProposalStatus, to: MatchProposalStatus): boolean => {
  return VALID_STATUS_TRANSITIONS[from].includes(to);
};

// ═══════════════════════════════════════════════════════════════
// FAIRNESS INDICATORS (SYSTEM-GENERATED, READ-ONLY)
// ═══════════════════════════════════════════════════════════════

/**
 * Fairness indicator categories for transparency
 * 
 * OWNERSHIP: SYSTEM-ONLY
 * These values are computed by the matching algorithm.
 * UI displays them for transparency but CANNOT modify them.
 */
export interface FairnessIndicators {
  /** Whether local candidate priority was applied */
  readonly localCandidateBoost: boolean;
  /** Whether diversity metrics were considered */
  readonly diversityConsideration: boolean;
  /** Tolerance for skill gap (0-100%) */
  readonly skillGapTolerance: number;
}

// ═══════════════════════════════════════════════════════════════
// MATCH EXPLANATION (SYSTEM-GENERATED, READ-ONLY)
// ═══════════════════════════════════════════════════════════════

/** Weight classification for explanation factors */
export type ExplanationWeight = 'high' | 'medium' | 'low';

/**
 * A system-generated match explanation entry
 * 
 * OWNERSHIP: SYSTEM-ONLY
 * UI displays these to explain "why" but never "how".
 * The algorithm details remain opaque.
 */
export interface MatchExplanationItem {
  /** Human-readable factor name */
  readonly factor: string;
  /** Explanation text for this factor */
  readonly value: string;
  /** Importance weight (affects display, not computation) */
  readonly weight: ExplanationWeight;
}

// ═══════════════════════════════════════════════════════════════
// MATCH PROPOSAL (CORE SYSTEM ENTITY)
// ═══════════════════════════════════════════════════════════════

/**
 * MatchProposal - System-generated candidate recommendation
 * 
 * ═══════════════════════════════════════════════════════════════
 * OWNERSHIP: SYSTEM-ONLY (IMMUTABLE AFTER GENERATION)
 * ═══════════════════════════════════════════════════════════════
 * 
 * Company CANNOT:
 * - Edit score
 * - Edit explanation
 * - See hidden student data
 * - See unmatched students
 * - Reorder proposals
 * - Filter proposals
 * 
 * Company CAN ONLY:
 * - View system-provided data
 * - Approve / Reject / Hold (binary acknowledgement)
 */
export interface MatchProposal {
  /** Unique match ID - SYSTEM-GENERATED */
  readonly id: string;
  /** Associated job ID */
  readonly jobId: string;
  /** Associated company ID (for authorization) */
  readonly companyId: string;
  
  // ─── Candidate Summary (LIMITED VISIBILITY) ───
  // Only system-approved fields are exposed
  /** Candidate identifier - SYSTEM USE ONLY */
  readonly candidateId: string;
  /** Candidate display name */
  readonly candidateName: string;
  /** Candidate course/qualification */
  readonly candidateCourse: string;
  /** Matched skills ONLY (not full profile) */
  readonly candidateSkills: readonly string[];
  
  // ─── System-Computed Metrics (READ-ONLY) ───
  /** Match score (0-100) - SYSTEM-OWNED, NOT EDITABLE */
  readonly score: number;
  /** Distance in km - SYSTEM-COMPUTED */
  readonly distanceKm: number;
  /** Preference alignment category */
  readonly preferenceAlignment: 'strong' | 'moderate' | 'weak';
  
  // ─── Explainability (READ-ONLY) ───
  /** Why this candidate was matched */
  readonly explanation: readonly MatchExplanationItem[];
  /** Fairness metrics applied */
  readonly fairnessIndicators: FairnessIndicators;
  
  // ─── Status (SYSTEM-CONTROLLED) ───
  /** Current status - transitions restricted by VALID_STATUS_TRANSITIONS */
  readonly status: MatchProposalStatus;
  
  // ─── Timestamps (SYSTEM-GENERATED) ───
  /** When this proposal was generated by matching engine */
  readonly generatedAt: string;
  /** When a company action was taken (if any) */
  readonly actionedAt?: string;
}

// ═══════════════════════════════════════════════════════════════
// COMPANY ACTIONS (LIMITED, BINARY ONLY)
// ═══════════════════════════════════════════════════════════════

/**
 * Input for company actions on matches
 * 
 * These are the ONLY actions a company can perform.
 * No editing, filtering, sorting, or browsing allowed.
 */
export type MatchAction = 'approve' | 'reject' | 'hold';

/**
 * All valid match actions - for runtime validation
 */
export const VALID_MATCH_ACTIONS: readonly MatchAction[] = ['approve', 'reject', 'hold'] as const;

/**
 * Validate if an action is valid
 */
export const isValidMatchAction = (action: string): action is MatchAction => {
  return VALID_MATCH_ACTIONS.includes(action as MatchAction);
};

// ═══════════════════════════════════════════════════════════════
// DERIVED TYPES (COMPUTED BY SYSTEM)
// ═══════════════════════════════════════════════════════════════

/**
 * Summary of match state for a job
 * DERIVED from MatchProposal[] - never stored directly
 */
export interface JobMatchSummary {
  readonly totalProposals: number;
  readonly approved: number;
  readonly rejected: number;
  readonly hold: number;
  readonly pending: number;
  readonly locked: number;
  readonly intakeRemaining: number;
}

// ═══════════════════════════════════════════════════════════════
// JOB STATUS LIFECYCLE (SYSTEM-OWNED)
// ═══════════════════════════════════════════════════════════════

/**
 * Valid job status transitions - SYSTEM-CONTROLLED
 * draft → processing (on submit)
 * processing → matched (on matching complete)
 * matched → closed (on intake full)
 */
export type JobStatus = 'draft' | 'processing' | 'matched' | 'closed';

export const VALID_JOB_TRANSITIONS: Record<JobStatus, readonly JobStatus[]> = {
  draft: ['processing'] as const,
  processing: ['matched'] as const,
  matched: ['closed'] as const,
  closed: [] as const, // Terminal
} as const;

/**
 * Check if a job status transition is valid
 */
export const isValidJobTransition = (from: JobStatus, to: JobStatus): boolean => {
  return VALID_JOB_TRANSITIONS[from].includes(to);
};
