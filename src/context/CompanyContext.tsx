/**
 * CompanyContext - Single source of truth for company state.
 * 
 * JWT-ONLY AUTH MODEL:
 * - All company/job data comes from backend
 * - Context NEVER stores domain data locally
 * - Context NEVER computes match scores
 * - On refresh: revalidate from backend
 * - After mutations: refetch state via refreshCompany()
 * 
 * CRITICAL RULES:
 * - refreshCompany() is the ONLY place company state is set
 * - Login functions do NOT return company
 * - Login functions do NOT set company state directly
 */
import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import * as companyApi from '@/api/company.api';
import * as companyJobsApi from '@/api/companyJobs.api';
import * as matchingApi from '@/api/matchingEngine.api';
import type { CompanyUser, CompanyJob, CreateJobInput } from '@/types/company';
import type { MatchProposal, JobMatchSummary, MatchAction } from '@/types/match';

interface CompanyState {
  isLoading: boolean;
  isInitialized: boolean;
  company: CompanyUser | null;
  jobs: CompanyJob[];
}

interface CompanyContextType extends CompanyState {
  // Auth actions - ALL return void, NEVER company
  loginCompany: (email: string, password: string) => Promise<void>;
  registerCompany: (email: string, password: string, companyName: string) => Promise<void>;
  logoutCompany: () => Promise<void>;
  
  // Profile
  updateCompanyProfile: (data: Partial<CompanyUser>) => Promise<CompanyUser>;
  
  // Jobs
  createJob: (data: CreateJobInput) => Promise<CompanyJob>;
  
  // Verification
  requestEmailOtp: (email: string) => Promise<void>;
  verifyEmailOtp: (email: string, otp: string) => Promise<void>;
  verifyGst: (gstNumber: string) => Promise<void>;
  
  // System Actions
  processJob: (jobId: string) => Promise<boolean>;
  runMatching: (jobId: string) => Promise<MatchProposal[]>;
  performMatchAction: (matchId: string, action: MatchAction) => Promise<MatchProposal>;
  getMatchesForJob: (jobId: string) => Promise<MatchProposal[]>;
  getJobMatchSummary: (jobId: string, intake: number) => Promise<JobMatchSummary>;
  
  // Hydration
  refreshCompany: () => Promise<void>;
  refreshJobs: () => Promise<void>;
  
  // Derived State
  isAuthenticated: boolean;
  isVerified: boolean;
  hasJobs: boolean;
}

const CompanyContext = createContext<CompanyContextType | undefined>(undefined);

export const CompanyProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [state, setState] = useState<CompanyState>({
    isLoading: false,
    isInitialized: false,
    company: null,
    jobs: [],
  });

  /**
   * Refresh jobs from backend
   */
  const refreshJobs = useCallback(async (): Promise<void> => {
    if (!state.company?.id) return;
    try {
      const jobs = await companyJobsApi.getCompanyJobs(state.company.id);
      setState(prev => ({ ...prev, jobs }));
    } catch (error) {
      console.error('[CompanyContext] Failed to refresh jobs:', error);
    }
  }, [state.company?.id]);

  /**
   * Refresh company from /company/me - SINGLE SOURCE OF TRUTH
   * THIS IS THE ONLY PLACE COMPANY STATE IS SET
   */
  const refreshCompany = useCallback(async (): Promise<void> => {
    try {
      const company = await companyApi.getCurrentCompany();
      if (company) {
        const jobs = await companyJobsApi.getCompanyJobs(company.id);
        setState(prev => ({ ...prev, company, jobs, isInitialized: true }));
      } else {
        setState(prev => ({ ...prev, company: null, jobs: [], isInitialized: true }));
      }
    } catch (error) {
      console.error('[CompanyContext] Failed to refresh company:', error);
      setState(prev => ({ ...prev, company: null, jobs: [], isInitialized: true }));
    }
  }, []);

  // Initialize on mount
  useEffect(() => {
    refreshCompany();
  }, [refreshCompany]);

  // Revalidate on tab focus
  useEffect(() => {
    const handleFocus = () => {
      refreshCompany();
    };
    window.addEventListener('focus', handleFocus);
    return () => window.removeEventListener('focus', handleFocus);
  }, [refreshCompany]);

  // ============================================================================
  // AUTH ACTIONS - All return void, all hydrate via refreshCompany()
  // ============================================================================

  /**
   * Login - stores JWT, then hydrates from /company/me
   */
  const loginCompany = async (email: string, password: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.loginCompany(email, password);
      await refreshCompany(); // Hydrate from /company/me
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  /**
   * Register - stores JWT, does NOT hydrate (redirect to verify)
   */
  const registerCompany = async (email: string, password: string, companyName: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.registerCompany(email, password, companyName);
      // Do NOT refresh - redirect to verification
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  /**
   * Logout - clears token and company state
   */
  const logoutCompany = async (): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.logoutCompany();
      setState(prev => ({ ...prev, company: null, jobs: [], isLoading: false }));
    } catch {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  // ============================================================================
  // PROFILE & JOBS
  // ============================================================================

  const updateCompanyProfile = async (data: Partial<CompanyUser>): Promise<CompanyUser> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const company = await companyApi.updateCompanyProfile(data);
      setState(prev => ({ ...prev, company, isLoading: false }));
      return company;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const createJob = async (data: CreateJobInput): Promise<CompanyJob> => {
    if (!state.company?.id) {
      throw new Error('No company session');
    }
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const job = await companyJobsApi.createJob(state.company.id, data);
      await refreshJobs();
      setState(prev => ({ ...prev, isLoading: false }));
      return job;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  // ============================================================================
  // VERIFICATION
  // ============================================================================

  const requestEmailOtp = async (email: string): Promise<void> => {
    await companyApi.requestCompanyEmailOtp(email);
  };

  /**
   * Verify email OTP - then hydrate from /company/me
   */
  const verifyEmailOtp = async (email: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.verifyCompanyEmailOtp(email, otp);
      await refreshCompany();
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const verifyGst = async (gstNumber: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.verifyCompanyGst(gstNumber);
      await refreshCompany();
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  // ============================================================================
  // SYSTEM ACTIONS
  // ============================================================================

  const processJob = async (jobId: string): Promise<boolean> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const result = await companyJobsApi.processJob(jobId);
      await refreshJobs();
      setState(prev => ({ ...prev, isLoading: false }));
      return result;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const runMatching = async (jobId: string): Promise<MatchProposal[]> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const proposals = await matchingApi.runMatching(jobId);
      await refreshJobs();
      setState(prev => ({ ...prev, isLoading: false }));
      return proposals;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const performMatchAction = async (matchId: string, action: MatchAction): Promise<MatchProposal> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const result = await matchingApi.performMatchAction(matchId, action);
      await refreshJobs();
      setState(prev => ({ ...prev, isLoading: false }));
      return result;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const getMatchesForJob = async (jobId: string): Promise<MatchProposal[]> => {
    return matchingApi.getMatchesForJob(jobId);
  };

  const getJobMatchSummary = async (jobId: string, intake: number): Promise<JobMatchSummary> => {
    return matchingApi.getJobMatchSummary(jobId, intake);
  };

  // Derived state - from backend response ONLY
  const isAuthenticated = !!state.company?.id;
  const isVerified = !!state.company?.emailVerified;
  const hasJobs = state.jobs.length > 0;

  return (
    <CompanyContext.Provider value={{
      ...state,
      loginCompany,
      registerCompany,
      logoutCompany,
      updateCompanyProfile,
      createJob,
      requestEmailOtp,
      verifyEmailOtp,
      verifyGst,
      processJob,
      runMatching,
      performMatchAction,
      getMatchesForJob,
      getJobMatchSummary,
      refreshCompany,
      refreshJobs,
      isAuthenticated,
      isVerified,
      hasJobs,
    }}>
      {children}
    </CompanyContext.Provider>
  );
};

export const useCompany = (): CompanyContextType => {
  const context = useContext(CompanyContext);
  if (!context) {
    throw new Error('useCompany must be used within a CompanyProvider');
  }
  return context;
};
