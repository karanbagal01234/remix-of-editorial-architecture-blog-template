// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// Authentication API - All logic is backend-authoritative
// Frontend ONLY collects credentials and sends to API

import api from '@/utils/api';
import type { UserData } from '@/types/student';

const AUTH_TOKEN_KEY = 'aura_access_token';
const REFRESH_TOKEN_KEY = 'aura_refresh_token';

// ============================================================================
// TOKEN MANAGEMENT - ONLY auth tokens stored locally
// ============================================================================

export const getAccessToken = (): string | null => {
  return localStorage.getItem(AUTH_TOKEN_KEY);
};

export const setTokens = (accessToken: string, refreshToken?: string): void => {
  localStorage.setItem(AUTH_TOKEN_KEY, accessToken);
  if (refreshToken) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
};

export const clearTokens = (): void => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
};

// ============================================================================
// API CALLS - Backend-authoritative
// ============================================================================

/**
 * Register new user with email and password
 * Backend creates user and sends verification OTP
 */
export const register = async (
  email: string, 
  password: string, 
  phone: string
): Promise<{ message: string }> => {
  const response = await api.post('/auth/register', { email, password, phone });
  return response.data;
};

/**
 * Login with email and password
 * Returns tokens if credentials valid
 */
export const login = async (
  email: string, 
  password: string
): Promise<{ user: UserData; accessToken: string; refreshToken: string }> => {
  const response = await api.post('/auth/login', { email, password });
  const { accessToken, refreshToken } = response.data;
  setTokens(accessToken, refreshToken);
  return response.data;
};

/**
 * Request OTP for email verification
 * Backend generates and sends OTP - frontend NEVER generates OTPs
 */
export const requestEmailOtp = async (email: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/otp/email/request', { email });
  return response.data;
};

/**
 * Verify email with OTP
 * Backend validates OTP - frontend NEVER validates OTPs
 */
export const verifyEmailOtp = async (email: string, otp: string): Promise<UserData> => {
  const response = await api.post('/auth/otp/email/verify', { email, otp });
  return response.data;
};

/**
 * Request OTP for phone verification
 * Backend generates and sends OTP
 */
export const requestPhoneOtp = async (phone: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/otp/phone/request', { phone });
  return response.data;
};

/**
 * Verify phone with OTP
 * Backend validates OTP
 */
export const verifyPhoneOtp = async (phone: string, otp: string): Promise<UserData> => {
  const response = await api.post('/auth/otp/phone/verify', { phone, otp });
  return response.data;
};

/**
 * Request password reset
 * Backend sends reset OTP to email
 */
export const requestPasswordReset = async (email: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/password/reset/request', { email });
  return response.data;
};

/**
 * Reset password with OTP
 */
export const resetPassword = async (
  email: string, 
  otp: string, 
  newPassword: string
): Promise<{ message: string }> => {
  const response = await api.post('/auth/password/reset/confirm', { email, otp, newPassword });
  return response.data;
};

/**
 * Get current user session
 * Backend validates token and returns user data
 * This is the ONLY source of truth for user state
 */
export const getCurrentUser = async (): Promise<UserData | null> => {
  const token = getAccessToken();
  if (!token) return null;
  
  try {
    const response = await api.get('/auth/me');
    return response.data;
  } catch (error) {
    // Token invalid or expired
    clearTokens();
    return null;
  }
};

/**
 * Refresh access token
 */
export const refreshToken = async (): Promise<string | null> => {
  const refresh = localStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refresh) return null;
  
  try {
    const response = await api.post('/auth/refresh', { refreshToken: refresh });
    const { accessToken, refreshToken: newRefresh } = response.data;
    setTokens(accessToken, newRefresh);
    return accessToken;
  } catch (error) {
    clearTokens();
    return null;
  }
};

/**
 * Logout - clears all tokens
 */
export const logout = async (): Promise<void> => {
  try {
    await api.post('/auth/logout');
  } catch (error) {
    // Ignore logout errors
  } finally {
    clearTokens();
  }
};
