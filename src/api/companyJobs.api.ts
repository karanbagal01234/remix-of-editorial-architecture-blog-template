/**
 * FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
 * 
 * Company Jobs API
 * 
 * Handles job creation and management for companies.
 * All state is backend-authoritative. Frontend only sends intent and renders outcome.
 * 
 * BACKEND CONTRACT:
 * - POST /api/company/jobs             → CompanyJob (create)
 * - GET  /api/company/jobs             → CompanyJob[]
 * - GET  /api/company/jobs/:id         → CompanyJob
 * - POST /api/company/jobs/:id/process → { success: boolean }
 * - DELETE /api/company/jobs/:id       → void (if allowed)
 */

import api from '@/utils/api';
import type { CompanyJob, CreateJobInput } from '@/types/company';

// ============================================================================
// API FUNCTIONS — BACKEND-READY HTTP STUBS
// ============================================================================

/**
 * Creates a new job in DRAFT status.
 * 
 * COMPANY INTENT: Company declares requirements.
 * 
 * BACKEND AUTHORITY:
 * - Backend generates job ID
 * - Backend sets initial status to 'draft'
 * - Backend records creation timestamp
 * - Backend validates company authorization
 * 
 * FRONTEND RESPONSIBILITY:
 * - Collect job details from form
 * - Disable UI during submission
 * - Handle validation errors
 */
export const createJob = async (
  companyId: string,
  data: CreateJobInput
): Promise<CompanyJob> => {
  const response = await api.post<CompanyJob>('/api/company/jobs', {
    companyId,
    ...data,
  });
  return response.data;
};

/**
 * Retrieves all jobs for the current company.
 * 
 * BACKEND AUTHORITY:
 * - Backend filters by authenticated company
 * - Backend returns current job statuses
 */
export const getCompanyJobs = async (companyId: string): Promise<CompanyJob[]> => {
  const response = await api.get<CompanyJob[]>('/api/company/jobs', {
    params: { companyId },
  });
  return response.data;
};

/**
 * Retrieves a specific job by ID.
 */
export const getJobById = async (jobId: string): Promise<CompanyJob | null> => {
  try {
    const response = await api.get<CompanyJob>(`/api/company/jobs/${jobId}`);
    return response.data;
  } catch (error: unknown) {
    // 404 means job not found
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
 * Submits a job for processing (NLP skill extraction).
 * 
 * SYSTEM ACTION: Only valid for jobs in 'draft' status.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates job is in draft status
 * - Backend runs NLP/AI skill extraction on JD
 * - Backend transitions job to 'processing' then 'active'
 * - Backend enforces idempotency (multiple calls are safe)
 * 
 * FRONTEND RESPONSIBILITY:
 * - Show processing indicator
 * - Poll or wait for status update
 * - Handle already-processed gracefully (200 OK)
 */
export const processJob = async (jobId: string): Promise<boolean> => {
  const response = await api.post<{ success: boolean }>(
    `/api/company/jobs/${jobId}/process`
  );
  return response.data.success;
};

/**
 * Deletes a job (if allowed by backend policy).
 * 
 * BACKEND AUTHORITY:
 * - Backend validates job can be deleted (e.g., only drafts)
 * - Backend removes job and related data
 * - Backend returns 403 if deletion not allowed
 */
export const deleteJob = async (jobId: string): Promise<void> => {
  await api.delete(`/api/company/jobs/${jobId}`);
};

/**
 * Clears all jobs for a company (used on logout/cleanup).
 * 
 * BACKEND AUTHORITY:
 * - Backend handles cleanup on logout via session invalidation
 * - This is a no-op on the frontend — included for API contract completeness
 */
export const clearCompanyJobs = async (companyId: string): Promise<void> => {
  await api.delete('/api/company/jobs', {
    params: { companyId },
  });
};
