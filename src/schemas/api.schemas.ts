/**
 * API Response Schemas - Structural Validation Only
 * 
 * RULES:
 * - Zod validates SHAPE ONLY
 * - No business rules
 * - No semantic inference
 * - No defaulting
 * - No silent coercion
 */

import { z } from 'zod';

// ============================================================================
// AUTH SCHEMAS
// ============================================================================

export const AuthTokenResponseSchema = z.object({
  access_token: z.string(),
});

export const AuthLoginResponseSchema = z.object({
  success: z.boolean(),
  user: z.object({
    id: z.string(),
    email: z.string(),
    name: z.string(),
    role: z.enum(['student', 'company']),
    emailVerified: z.boolean(),
    phoneVerified: z.boolean(),
    status: z.string(),
    createdAt: z.string(),
  }),
  access_token: z.string(),
});

export const AuthMeResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string(),
  phone: z.string().optional().nullable(),
  role: z.enum(['student', 'company']).optional(),
  location: z.object({
    lat: z.number(),
    lng: z.number(),
  }).nullable().optional(),
  skills: z.array(z.string()).optional(),
  resume: z.string().nullable().optional(),
  preferences: z.object({
    domains: z.array(z.string()),
    workStyle: z.enum(['remote', 'hybrid', 'onsite']),
    distance: z.number(),
    stipend: z.number().nullable(),
  }).nullable().optional(),
  status: z.string(),
  emailVerified: z.boolean(),
  phoneVerified: z.boolean(),
  token: z.string().nullable().optional(),
  matchResult: z.object({
    companyId: z.string(),
    companyName: z.string(),
    score: z.number(),
    explanation: z.array(z.string()),
    status: z.enum(['matched', 'waitlist', 'rejected']),
  }).nullable().optional(),
  onboardingComplete: z.boolean().optional(),
  createdAt: z.string(),
});

export const OtpResponseSchema = z.object({
  success: z.boolean().optional(),
  message: z.string(),
  expiresIn: z.number().optional(),
});

export const MessageResponseSchema = z.object({
  message: z.string(),
  success: z.boolean().optional(),
});

// ============================================================================
// USER DATA SCHEMA
// ============================================================================

export const UserDataSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string(),
  phone: z.string(),
  location: z.object({
    lat: z.number(),
    lng: z.number(),
  }).nullable(),
  skills: z.array(z.string()),
  resume: z.string().nullable(),
  preferences: z.object({
    domains: z.array(z.string()),
    workStyle: z.enum(['remote', 'hybrid', 'onsite']),
    distance: z.number(),
    stipend: z.number().nullable(),
  }).nullable(),
  status: z.string(),
  emailVerified: z.boolean(),
  phoneVerified: z.boolean(),
  token: z.string().nullable(),
  matchResult: z.object({
    companyId: z.string(),
    companyName: z.string(),
    score: z.number(),
    explanation: z.array(z.string()),
    status: z.enum(['matched', 'waitlist', 'rejected']),
  }).nullable(),
  onboardingComplete: z.boolean(),
  createdAt: z.string(),
});

// ============================================================================
// RESUME SCHEMAS
// ============================================================================

export const ResumeVersionSchema = z.object({
  resumeId: z.string(),
  version: z.number(),
  fileName: z.string(),
  uploadedAt: z.string(),
  status: z.enum(['active', 'archived', 'pending_extraction']),
  extractedSkills: z.array(z.string()),
  skillsConfirmed: z.boolean(),
  fileSize: z.number(),
});

export const ResumeHistorySchema = z.object({
  currentVersion: ResumeVersionSchema.nullable(),
  archivedVersions: z.array(ResumeVersionSchema),
});

export const SkillsExtractResponseSchema = z.object({
  skills: z.array(z.string()),
});

// ============================================================================
// OFFER SCHEMAS
// ============================================================================

export const OfferSchema = z.object({
  offerId: z.string(),
  matchId: z.string(),
  jobId: z.string(),
  companyId: z.string(),
  companyName: z.string(),
  roleTitle: z.string(),
  location: z.string(),
  matchScore: z.number(),
  status: z.enum(['pending', 'accepted', 'declined', 'expired', 'withdrawn', 'superseded']),
  createdAt: z.string(),
  decisionDeadline: z.string(),
  decidedAt: z.string().nullable(),
  resumeVersionUsed: z.number(),
  explanation: z.array(z.string()),
  systemNote: z.string().nullable(),
});

export const OffersListResponseSchema = z.object({
  offers: z.array(OfferSchema),
});

export const OfferActionResponseSchema = z.object({
  success: z.boolean(),
  offer: OfferSchema,
});

// ============================================================================
// REVIEW SCHEMAS
// ============================================================================

export const ReviewRequestSchema = z.object({
  reviewId: z.string(),
  matchId: z.string(),
  reason: z.enum([
    'skills_misinterpreted',
    'resume_context_ignored',
    'domain_mismatch',
    'location_logic_incorrect',
    'other',
  ]),
  otherReason: z.string().nullable(),
  createdAt: z.string(),
  status: z.enum(['submitted', 'under_review', 'resolved']),
  resolvedAt: z.string().nullable(),
  resolution: z.string().nullable(),
});

export const ReviewsListResponseSchema = z.object({
  reviews: z.array(ReviewRequestSchema),
});

// ============================================================================
// MATCH SCHEMAS
// ============================================================================

export const MatchResultSchema = z.object({
  companyId: z.string(),
  companyName: z.string(),
  score: z.number(),
  explanation: z.array(z.string()),
  status: z.enum(['matched', 'waitlist', 'rejected']),
});

// ============================================================================
// APPLICATION SCHEMAS
// ============================================================================

export const ApplicationStateSchema = z.object({
  status: z.enum(['active', 'withdrawn', 'cooldown', 'completed']),
  withdrawnAt: z.string().nullable(),
  cooldownEndsAt: z.string().nullable(),
  cooldownDays: z.number(),
  canReapply: z.boolean(),
  withdrawalReason: z.string().nullable(),
});

// ============================================================================
// DASHBOARD SCHEMAS
// ============================================================================

export const DashboardPayloadSchema = z.object({
  user: UserDataSchema.optional(),
  offers: z.array(OfferSchema).optional(),
  reviews: z.array(ReviewRequestSchema).optional(),
  applicationState: ApplicationStateSchema.optional(),
  stats: z.object({
    totalOffers: z.number(),
    pendingOffers: z.number(),
    acceptedOffers: z.number(),
  }).optional(),
});

// ============================================================================
// COMPANY SCHEMAS
// ============================================================================

export const CompanyUserSchema = z.object({
  id: z.string(),
  companyName: z.string(),
  email: z.string(),
  contactPerson: z.string().optional(),
  gstNumber: z.string().optional(),
  emailVerified: z.boolean(),
  token: z.string().nullable(),
  status: z.enum(['profile-pending', 'active']),
  createdAt: z.string(),
});

export const CompanyJobSchema = z.object({
  id: z.string(),
  companyId: z.string(),
  title: z.string(),
  requiredSkills: z.array(z.string()),
  location: z.object({
    lat: z.number(),
    lng: z.number(),
    label: z.string(),
  }),
  intake: z.number(),
  stipend: z.number().optional(),
  perks: z.string().optional(),
  originalJD: z.string(),
  status: z.enum(['draft', 'processing', 'matched', 'closed']),
  createdAt: z.string(),
  processedAt: z.string().optional(),
  closedAt: z.string().optional(),
});

export const CompanyJobsListResponseSchema = z.object({
  jobs: z.array(CompanyJobSchema),
});

export const CompanyMatchProposalSchema = z.object({
  matchId: z.string(),
  studentId: z.string(),
  score: z.number(),
  skills: z.array(z.string()),
  explanation: z.array(z.string()),
  status: z.enum(['proposed', 'approved', 'rejected']),
});

export const CompanyMatchesResponseSchema = z.object({
  matches: z.array(CompanyMatchProposalSchema),
});

// ============================================================================
// TYPE EXPORTS
// ============================================================================

export type AuthLoginResponse = z.infer<typeof AuthLoginResponseSchema>;
export type AuthMeResponse = z.infer<typeof AuthMeResponseSchema>;
export type UserDataSchemaType = z.infer<typeof UserDataSchema>;
export type ResumeVersionType = z.infer<typeof ResumeVersionSchema>;
export type OfferType = z.infer<typeof OfferSchema>;
export type ReviewRequestType = z.infer<typeof ReviewRequestSchema>;
export type CompanyUserType = z.infer<typeof CompanyUserSchema>;
export type CompanyJobType = z.infer<typeof CompanyJobSchema>;
