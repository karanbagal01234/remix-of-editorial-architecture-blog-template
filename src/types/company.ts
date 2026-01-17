// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// Single source of truth for all company-related types

export type CompanyStatus = 'profile-pending' | 'active';

/**
 * CompanyUser - Backend-authoritative company profile
 * IMPORTANT: All fields are READ-ONLY from frontend perspective
 */
export interface CompanyUser {
  id: string;
  companyName: string;
  email: string;
  contactPerson: string;
  gstNumber: string;
  /** Email verified via OTP */
  emailVerified: boolean;
  token: string | null;
  status: CompanyStatus;
  createdAt: string;
}

export type CompanyFlowStep = 'verify' | 'profile' | 'create-job' | 'job-status' | 'job-matches';

// ============= JOB-RELATED TYPES =============

/**
 * Job status is SYSTEM-OWNED. Companies cannot mutate status directly.
 * - draft: Job created but not yet submitted for processing
 * - processing: System is analyzing requirements (NLP extraction)
 * - matched: Matching complete, candidates available (Layer 3)
 * - closed: Job filled or manually closed
 */
export type CompanyJobStatus = 'draft' | 'processing' | 'matched' | 'closed';

export interface JobLocation {
  lat: number;
  lng: number;
  label: string;
}

export interface CompanyJob {
  id: string;
  companyId: string;
  title: string;
  requiredSkills: string[];
  location: JobLocation;
  intake: number;
  stipend?: number;
  perks?: string;
  /** Original JD text pasted by company - stored for audit/matching */
  originalJD: string;
  /** System-owned status - company cannot directly mutate */
  status: CompanyJobStatus;
  createdAt: string;
  /** Set by system when job enters processing */
  processedAt?: string;
  /** Set by system when job is closed */
  closedAt?: string;
}

/** Input for creating a job - excludes all system-owned fields */
export type CreateJobInput = Omit<CompanyJob, 'id' | 'companyId' | 'status' | 'createdAt' | 'processedAt' | 'closedAt'>;
