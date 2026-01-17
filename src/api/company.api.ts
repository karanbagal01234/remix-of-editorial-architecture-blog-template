// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// Company API - All logic is backend-authoritative
// Frontend ONLY collects data and sends to API

import api from '@/utils/api';
import type { CompanyUser } from '@/types/company';

const COMPANY_TOKEN_KEY = 'aura_company_token';

// ============================================================================
// TOKEN MANAGEMENT
// ============================================================================

export const getCompanyToken = (): string | null => {
  return localStorage.getItem(COMPANY_TOKEN_KEY);
};

export const setCompanyToken = (token: string): void => {
  localStorage.setItem(COMPANY_TOKEN_KEY, token);
};

export const clearCompanyToken = (): void => {
  localStorage.removeItem(COMPANY_TOKEN_KEY);
};

// ============================================================================
// AUTH APIs - Backend-authoritative
// ============================================================================

/**
 * Register company with email and password
 */
export const registerCompany = async (
  email: string,
  password: string,
  companyName: string
): Promise<{ message: string }> => {
  const response = await api.post('/company/auth/register', { email, password, companyName });
  return response.data;
};

/**
 * Login company
 */
export const loginCompany = async (
  email: string,
  password: string
): Promise<{ company: CompanyUser; token: string }> => {
  const response = await api.post('/company/auth/login', { email, password });
  const { company, token } = response.data;
  setCompanyToken(token);
  return response.data;
};

/**
 * Get current company session
 */
export const getCurrentCompany = async (): Promise<CompanyUser | null> => {
  const token = getCompanyToken();
  if (!token) return null;
  
  try {
    const response = await api.get('/company/auth/me');
    return response.data;
  } catch (error) {
    clearCompanyToken();
    return null;
  }
};

/**
 * Request email OTP for company verification
 */
export const requestCompanyEmailOtp = async (email: string): Promise<{ message: string }> => {
  const response = await api.post('/company/auth/otp/request', { email });
  return response.data;
};

/**
 * Verify company email with OTP
 */
export const verifyCompanyEmailOtp = async (email: string, otp: string): Promise<CompanyUser> => {
  const response = await api.post('/company/auth/otp/verify', { email, otp });
  return response.data;
};

/**
 * Verify company with GST number
 * Backend validates GST - frontend just submits
 */
export const verifyCompanyGst = async (gstNumber: string): Promise<CompanyUser> => {
  const response = await api.post('/company/verify/gst', { gstNumber });
  return response.data;
};

/**
 * Update company profile
 */
export const updateCompanyProfile = async (data: Partial<CompanyUser>): Promise<CompanyUser> => {
  const response = await api.patch('/company/profile', data);
  return response.data;
};

/**
 * Logout company
 */
export const logoutCompany = async (): Promise<void> => {
  try {
    await api.post('/company/auth/logout');
  } catch (error) {
    // Ignore logout errors
  } finally {
    clearCompanyToken();
  }
};
