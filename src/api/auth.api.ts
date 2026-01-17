/**
 * Authentication API - JWT-Only Model
 * 
 * STRICT RULES:
 * - Backend issues ONE JWT ONLY
 * - NO refresh token
 * - NO silent refresh
 * - Frontend NEVER trusts login response user object
 * - ALL state derived from /auth/me
 */

import api from '@/utils/api';
import { toast } from 'sonner';
import { AuthLoginResponseSchema, AuthMeResponseSchema, OtpResponseSchema, MessageResponseSchema } from '@/schemas/api.schemas';
import type { UserData } from '@/types/student';

const AUTH_TOKEN_KEY = 'aura_access_token';

// ============================================================================
// TOKEN MANAGEMENT - JWT ONLY
// ============================================================================

export const getAccessToken = (): string | null => {
  return localStorage.getItem(AUTH_TOKEN_KEY);
};

export const setToken = (accessToken: string): void => {
  localStorage.setItem(AUTH_TOKEN_KEY, accessToken);
};

export const clearToken = (): void => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
};

// ============================================================================
// GOOGLE OAUTH
// ============================================================================

/**
 * Initiate Google OAuth flow
 * Frontend redirects to backend OAuth URL
 * Backend handles Google consent screen and returns JWT
 */
export const initiateGoogleOAuth = (): void => {
  const apiUrl = import.meta.env.VITE_API_URL || '/api';
  const redirectUrl = `${window.location.origin}/auth/callback`;
  window.location.href = `${apiUrl}/auth/google?redirect_uri=${encodeURIComponent(redirectUrl)}`;
};

/**
 * Handle OAuth callback
 * Backend has already validated Google auth and issued JWT in URL params
 */
export const handleOAuthCallback = async (token: string): Promise<UserData | null> => {
  if (!token) {
    toast.error('Authentication failed: No token received');
    return null;
  }
  
  setToken(token);
  return await getCurrentUser();
};

// ============================================================================
// API CALLS - BACKEND AUTHORITATIVE
// ============================================================================

/**
 * Register new user
 */
export const register = async (
  email: string, 
  password: string, 
  phone: string
): Promise<{ message: string }> => {
  const response = await api.post('/auth/register', { email, password, phone });
  const validated = MessageResponseSchema.safeParse(response.data);
  
  if (!validated.success || !validated.data.message) {
    toast.error('Invalid response format from server');
    throw new Error('Schema validation failed');
  }
  
  return { message: validated.data.message };
};

/**
 * Login with email and password
 * IMPORTANT: Do NOT trust user object from response
 * Frontend MUST call /auth/me to get authoritative state
 */
export const login = async (
  email: string, 
  password: string
): Promise<{ user: UserData; access_token: string }> => {
  const response = await api.post('/auth/login', { email, password });
  const validated = AuthLoginResponseSchema.safeParse(response.data);
  
  if (!validated.success) {
    toast.error('Invalid login response format');
    throw new Error('Schema validation failed');
  }
  
  // Store token
  setToken(validated.data.access_token);
  
  // CRITICAL: Immediately fetch authoritative user state
  const user = await getCurrentUser();
  if (!user) {
    toast.error('Failed to verify session');
    throw new Error('Session verification failed');
  }
  
  return { user, access_token: validated.data.access_token };
};

/**
 * Request OTP for email verification
 */
export const requestEmailOtp = async (email: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/otp/email/request', { email });
  const validated = OtpResponseSchema.safeParse(response.data);
  
  if (!validated.success || !validated.data.message) {
    toast.error('Invalid OTP response format');
    throw new Error('Schema validation failed');
  }
  
  return { message: validated.data.message };
};

/**
 * Verify email with OTP
 */
export const verifyEmailOtp = async (email: string, otp: string): Promise<UserData> => {
  const response = await api.post('/auth/otp/email/verify', { email, otp });
  const validated = AuthMeResponseSchema.safeParse(response.data);
  
  if (!validated.success) {
    toast.error('Invalid verification response');
    throw new Error('Schema validation failed');
  }
  
  return validated.data as UserData;
};

/**
 * Request OTP for phone verification
 */
export const requestPhoneOtp = async (phone: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/otp/phone/request', { phone });
  const validated = OtpResponseSchema.safeParse(response.data);
  
  if (!validated.success || !validated.data.message) {
    toast.error('Invalid OTP response format');
    throw new Error('Schema validation failed');
  }
  
  return { message: validated.data.message };
};

/**
 * Verify phone with OTP
 */
export const verifyPhoneOtp = async (phone: string, otp: string): Promise<UserData> => {
  const response = await api.post('/auth/otp/phone/verify', { phone, otp });
  const validated = AuthMeResponseSchema.safeParse(response.data);
  
  if (!validated.success) {
    toast.error('Invalid verification response');
    throw new Error('Schema validation failed');
  }
  
  return validated.data as UserData;
};

/**
 * Request password reset
 */
export const requestPasswordReset = async (email: string): Promise<{ message: string }> => {
  const response = await api.post('/auth/password/reset/request', { email });
  const validated = MessageResponseSchema.safeParse(response.data);
  
  if (!validated.success || !validated.data.message) {
    toast.error('Invalid response format');
    throw new Error('Schema validation failed');
  }
  
  return { message: validated.data.message };
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
  const validated = MessageResponseSchema.safeParse(response.data);
  
  if (!validated.success || !validated.data.message) {
    toast.error('Invalid response format');
    throw new Error('Schema validation failed');
  }
  
  return { message: validated.data.message };
};

/**
 * Get current user session
 * This is the ONLY source of truth for user state
 * If this fails → session is invalid
 */
export const getCurrentUser = async (): Promise<UserData | null> => {
  const token = getAccessToken();
  if (!token) return null;
  
  try {
    const response = await api.get('/auth/me');
    const validated = AuthMeResponseSchema.safeParse(response.data);
    
    if (!validated.success) {
      console.error('User data schema validation failed:', validated.error);
      toast.error('Invalid user data format received');
      clearToken();
      return null;
    }
    
    return validated.data as UserData;
  } catch (error) {
    // Token invalid or expired - session is invalid
    clearToken();
    return null;
  }
};

/**
 * Logout - clears token
 */
export const logout = async (): Promise<void> => {
  try {
    await api.post('/auth/logout');
  } catch {
    // Ignore logout errors - clear token regardless
  } finally {
    clearToken();
  }
};
