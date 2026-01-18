/**
 * Auth API - JWT-Only Authentication
 * 
 * SESSION MODEL:
 * - Backend issues ONE JWT only
 * - JWT expires → backend returns 401
 * - Frontend clears token and redirects to /login
 * - User must re-authenticate
 * - NO silent renewal, NO background refresh
 */

import api from '@/utils/api';
import { toast } from 'sonner';
import { 
  AuthLoginResponseSchema, 
  AuthMeResponseSchema, 
  OtpResponseSchema,
  MessageResponseSchema,
} from '@/schemas/api.schemas';
import type { UserData } from '@/types/student';

const AUTH_TOKEN_KEY = 'aura_access_token';

// ============================================================================
// TOKEN MANAGEMENT - JWT ONLY (NO REFRESH TOKEN)
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
// AUTH FUNCTIONS - LOGIN FUNCTIONS RETURN VOID
// ============================================================================

/**
 * Login with email/password
 * 
 * CONTRACT:
 * - Stores JWT only
 * - Does NOT return user
 * - Caller MUST call getCurrentUser() after to hydrate state
 */
export const login = async (email: string, password: string): Promise<void> => {
  try {
    const response = await api.post('/auth/login', { email, password });
    
    // Validate response shape
    const parsed = AuthLoginResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: login response');
    }
    
    // Store JWT only
    setToken(parsed.data.access_token);
    
    // Do NOT return user - caller must use /auth/me
  } catch (error) {
    toast.error('Login failed. Please check your credentials.');
    throw error;
  }
};

/**
 * Register new user
 * 
 * CONTRACT:
 * - Stores JWT if returned
 * - Does NOT return user
 * - Caller should redirect to email verification
 */
export const register = async (email: string, password: string, phone: string): Promise<void> => {
  try {
    const response = await api.post('/auth/register', { 
      email, 
      password, 
      phone,
      role: 'student',
    });
    
    const parsed = AuthLoginResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: register response');
    }
    
    // Store JWT
    setToken(parsed.data.access_token);
    
  } catch (error) {
    toast.error('Registration failed. Please try again.');
    throw error;
  }
};

/**
 * Get current user from /auth/me
 * 
 * THIS IS THE ONLY SOURCE OF TRUTH FOR USER STATE
 */
export const getCurrentUser = async (): Promise<UserData | null> => {
  const token = getAccessToken();
  if (!token) return null;
  
  try {
    const response = await api.get('/auth/me');
    
    const parsed = AuthMeResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      console.error('[Auth] Schema validation failed for /auth/me:', parsed.error);
      toast.error('Invalid user data received');
      throw new Error('Schema validation failed: auth/me response');
    }
    
    return parsed.data as UserData;
  } catch (error) {
    // 401 is handled by axios interceptor
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
    // Ignore errors - clear token anyway
  } finally {
    clearToken();
  }
};

// ============================================================================
// OTP VERIFICATION
// ============================================================================

export const requestEmailOtp = async (email: string): Promise<void> => {
  try {
    const response = await api.post('/auth/request-email-otp', { email });
    
    const parsed = OtpResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: email OTP request');
    }
    
    toast.success(parsed.data.message || 'OTP sent to your email');
  } catch (error) {
    toast.error('Failed to send OTP. Please try again.');
    throw error;
  }
};

export const verifyEmailOtp = async (email: string, otp: string): Promise<void> => {
  try {
    const response = await api.post('/auth/verify-email-otp', { email, otp });
    
    const parsed = MessageResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: email OTP verify');
    }
    
    toast.success('Email verified successfully');
  } catch (error) {
    toast.error('Invalid or expired OTP');
    throw error;
  }
};

export const requestPhoneOtp = async (phone: string): Promise<void> => {
  try {
    const response = await api.post('/auth/request-phone-otp', { phone });
    
    const parsed = OtpResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: phone OTP request');
    }
    
    toast.success(parsed.data.message || 'OTP sent to your phone');
  } catch (error) {
    toast.error('Failed to send OTP. Please try again.');
    throw error;
  }
};

export const verifyPhoneOtp = async (phone: string, otp: string): Promise<void> => {
  try {
    const response = await api.post('/auth/verify-phone-otp', { phone, otp });
    
    const parsed = MessageResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      toast.error('Invalid response from server');
      throw new Error('Schema validation failed: phone OTP verify');
    }
    
    toast.success('Phone verified successfully');
  } catch (error) {
    toast.error('Invalid or expired OTP');
    throw error;
  }
};

// ============================================================================
// GOOGLE OAUTH - BACKEND REDIRECT FLOW
// ============================================================================

/**
 * Initiate Google OAuth
 * 
 * CONTRACT:
 * - Frontend NEVER talks to Google directly
 * - Frontend redirects to backend OAuth URL
 * - Backend handles consent screen
 * - Backend redirects back with JWT in URL params
 */
export const initiateGoogleOAuth = (): void => {
  const apiBaseUrl = import.meta.env.VITE_API_URL;
  if (!apiBaseUrl) {
    toast.error('OAuth not configured');
    throw new Error('VITE_API_URL required for OAuth');
  }
  
  const callbackUrl = `${window.location.origin}/auth/callback`;
  const oauthUrl = `${apiBaseUrl}/auth/google?redirect_uri=${encodeURIComponent(callbackUrl)}`;
  
  window.location.href = oauthUrl;
};

/**
 * Handle OAuth callback
 * 
 * CONTRACT:
 * - Stores JWT from URL params
 * - Returns void
 * - Caller MUST call getCurrentUser() to hydrate state
 */
export const handleOAuthCallback = async (token: string): Promise<void> => {
  if (!token) {
    toast.error('No authentication token received');
    throw new Error('OAuth callback missing token');
  }
  
  // Store JWT
  setToken(token);
  
  // Verify session is valid by calling /auth/me
  const user = await getCurrentUser();
  if (!user) {
    clearToken();
    toast.error('Failed to verify authentication');
    throw new Error('OAuth session verification failed');
  }
  
  // Token is valid - do NOT return user
  // Caller will hydrate via refreshUser()
};
