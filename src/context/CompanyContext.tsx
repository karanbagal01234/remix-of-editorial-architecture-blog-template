// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * CompanyContext - Single source of truth for company state.
 * 
 * ═══════════════════════════════════════════════════════════════
 * BACKEND AUTHORITY MODEL
 * ═══════════════════════════════════════════════════════════════
 * 
 * - All company/job data comes from backend
 * - Context NEVER stores domain data locally
 * - Context NEVER computes match scores
 * - On refresh: revalidate from backend
 * - After mutations: refetch state
 * 
 * OWNERSHIP BOUNDARIES:
 * - COMPANY INTENT: login, updateProfile, createJob, logout
 * - SYSTEM ACTIONS: verifyGst, processJob, runMatching
 * - READ-ONLY: getMatches, getSummary
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
  // === COMPANY INTENT ACTIONS ===
  loginCompany: (email: string, password: string) => Promise<CompanyUser>;
  registerCompany: (email: string, password: string, companyName: string) => Promise<void>;
  updateCompanyProfile: (data: Partial<CompanyUser>) => Promise<CompanyUser>;
  createJob: (data: CreateJobInput) => Promise<CompanyJob>;
  logoutCompany: () => Promise<void>;
  
  // === VERIFICATION ===
  requestEmailOtp: (email: string) => Promise<void>;
  verifyEmailOtp: (email: string, otp: string) => Promise<void>;
  verifyGst: (gstNumber: string) => Promise<void>;
  
  // === SYSTEM ACTIONS ===
  processJob: (jobId: string) => Promise<boolean>;
  runMatching: (jobId: string) => Promise<MatchProposal[]>;
  performMatchAction: (matchId: string, action: MatchAction) => Promise<MatchProposal>;
  getMatchesForJob: (jobId: string) => Promise<MatchProposal[]>;
  getJobMatchSummary: (jobId: string, intake: number) => Promise<JobMatchSummary>;
  
  // === REFRESH UTILITIES ===
  refreshCompany: () => Promise<void>;
  refreshJobs: () => Promise<void>;
  
  // === DERIVED STATE ===
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
   * Full company refresh from backend
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

  // === COMPANY INTENT ACTIONS ===

  const loginCompany = async (email: string, password: string): Promise<CompanyUser> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const result = await companyApi.loginCompany(email, password);
      setState(prev => ({ ...prev, company: result.company, jobs: [], isLoading: false }));
      return result.company;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const registerCompany = async (email: string, password: string, companyName: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.registerCompany(email, password, companyName);
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

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
      await refreshJobs(); // Sync from backend
      setState(prev => ({ ...prev, isLoading: false }));
      return job;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const logoutCompany = async (): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.logoutCompany();
      setState(prev => ({ ...prev, company: null, jobs: [], isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  // === VERIFICATION ===

  const requestEmailOtp = async (email: string): Promise<void> => {
    await companyApi.requestCompanyEmailOtp(email);
  };

  const verifyEmailOtp = async (email: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.verifyCompanyEmailOtp(email, otp);
      await refreshCompany();
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const verifyGst = async (gstNumber: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await companyApi.verifyCompanyGst(gstNumber);
      await refreshCompany();
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  // === SYSTEM ACTIONS ===

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
  const isAuthenticated = !!state.company?.token;
  const isVerified = !!state.company?.emailVerified;
  const hasJobs = state.jobs.length > 0;

  return (
    <CompanyContext.Provider value={{
      ...state,
      // Company intent
      loginCompany,
      registerCompany,
      updateCompanyProfile,
      createJob,
      logoutCompany,
      // Verification
      requestEmailOtp,
      verifyEmailOtp,
      verifyGst,
      // System actions
      processJob,
      runMatching,
      performMatchAction,
      getMatchesForJob,
      getJobMatchSummary,
      // Utilities
      refreshCompany,
      refreshJobs,
      // Derived
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
