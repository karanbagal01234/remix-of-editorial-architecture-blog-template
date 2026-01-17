// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * CompanyFlowGuard - Protects company routes and enforces flow order.
 * 
 * ═══════════════════════════════════════════════════════════════
 * FLOW ENFORCEMENT RULES
 * ═══════════════════════════════════════════════════════════════
 * 
 * Rules:
 * - Not authenticated → /company/login
 * - Not verified → /company/verify-email
 * - Profile incomplete → /company/profile
 * - No jobs for job-status → /company/jobs/create
 * - Job matches requires job status >= matched
 * 
 * NEVER allows white screens or silent failures.
 * All redirects are logged for debugging.
 * 
 * MATCHING PAGE GUARDS:
 * - Job must exist
 * - Job status must be 'matched' or 'closed'
 * - Company must own the job
 */
import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useCompany } from '@/context/CompanyContext';
import LoadingSkeleton from '@/components/LoadingSkeleton';
import type { CompanyFlowStep } from '@/types/company';

interface CompanyFlowGuardProps {
  children: React.ReactNode;
  step: CompanyFlowStep;
  /** For job-matches step, validates against this jobId param */
  jobIdParam?: string;
}

const CompanyFlowGuard: React.FC<CompanyFlowGuardProps> = ({ children, step, jobIdParam }) => {
  const navigate = useNavigate();
  const params = useParams<{ jobId?: string }>();
  const jobId = jobIdParam || params.jobId;
  const { company, isAuthenticated, isVerified, isInitialized, hasJobs, jobs } = useCompany();
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    // Wait for context initialization
    if (!isInitialized) return;

    // === AUTHENTICATION CHECK ===
    if (!isAuthenticated) {
      console.info('[CompanyFlowGuard] Not authenticated, redirecting to login');
      navigate('/company/login', { replace: true });
      return;
    }

    // === STEP-SPECIFIC VALIDATION ===
    switch (step) {
      case 'verify':
        // Already verified → skip to profile
        if (isVerified) {
          navigate('/company/profile', { replace: true });
          return;
        }
        break;

      case 'profile':
        // Must be verified first
        if (!isVerified) {
          console.info('[CompanyFlowGuard] Not verified, redirecting to verify');
          navigate('/company/verify-email', { replace: true });
          return;
        }
        break;

      case 'create-job':
        // Must be verified
        if (!isVerified) {
          console.info('[CompanyFlowGuard] Not verified, redirecting to verify');
          navigate('/company/verify-email', { replace: true });
          return;
        }
        break;

      case 'job-status':
        // Must be verified
        if (!isVerified) {
          console.info('[CompanyFlowGuard] Not verified, redirecting to verify');
          navigate('/company/verify-email', { replace: true });
          return;
        }
        
        // Must have at least one job
        if (!hasJobs) {
          console.info('[CompanyFlowGuard] No jobs found, redirecting to create');
          navigate('/company/jobs/create', { replace: true });
          return;
        }
        
        // Validate job data integrity
        const hasValidJobs = jobs.every(job => 
          job.id && job.title && job.status && job.companyId === company?.id
        );
        if (!hasValidJobs) {
          console.warn('[CompanyFlowGuard] Corrupted job data detected');
          navigate('/company/jobs/create', { replace: true });
          return;
        }
        break;

      case 'job-matches':
        // === MATCHING PAGE GUARDS (STRICT) ===
        
        // Must be verified
        if (!isVerified) {
          console.info('[CompanyFlowGuard] Not verified, redirecting to verify');
          navigate('/company/verify-email', { replace: true });
          return;
        }
        
        // Must have jobId param
        if (!jobId) {
          console.warn('[CompanyFlowGuard] No jobId for matches, redirecting to status');
          navigate('/company/jobs/status', { replace: true });
          return;
        }
        
        // Job must exist
        const matchJob = jobs.find(j => j.id === jobId);
        if (!matchJob) {
          console.warn('[CompanyFlowGuard] Job not found for matches:', jobId);
          navigate('/company/jobs/status', { replace: true });
          return;
        }
        
        // Company must own the job
        if (matchJob.companyId !== company?.id) {
          console.warn('[CompanyFlowGuard] Job ownership mismatch');
          navigate('/company/jobs/status', { replace: true });
          return;
        }
        
        // Job must be in 'matched' or 'closed' status (system-controlled)
        if (matchJob.status !== 'matched' && matchJob.status !== 'closed') {
          console.info('[CompanyFlowGuard] Job not ready for matches. Status:', matchJob.status);
          navigate('/company/jobs/status', { replace: true });
          return;
        }
        break;
    }

    // All checks passed
    setShouldRender(true);
  }, [isInitialized, isAuthenticated, isVerified, hasJobs, jobs, company, step, jobId, navigate]);

  // Show loading while initializing
  if (!isInitialized) {
    return <LoadingSkeleton type="card" />;
  }

  // Show loading while checking guards
  if (!shouldRender) {
    return <LoadingSkeleton type="card" />;
  }

  return <>{children}</>;
};

export default CompanyFlowGuard;
