/**
 * UIContext - Single source of truth for UI state
 * 
 * JWT-ONLY AUTH MODEL:
 * - All user data comes from /auth/me
 * - Context NEVER computes verification status
 * - Context NEVER stores domain data
 * - On refresh: revalidate from /auth/me
 * - After mutations: refetch state from /auth/me
 * 
 * CRITICAL RULES:
 * - refreshUser() is the ONLY place user state is set
 * - Login functions do NOT return user
 * - Login functions do NOT set user state directly
 */
import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import * as authApi from '@/api/auth.api';
import type { UserData } from '@/types/student';

interface UIState {
  isLoading: boolean;
  isInitialized: boolean;
  sidebarOpen: boolean;
  theme: 'light' | 'dark';
  user: UserData | null;
}

interface UIContextType extends UIState {
  setLoading: (loading: boolean) => void;
  toggleSidebar: () => void;
  toggleTheme: () => void;
  
  // Auth actions - ALL return void, NEVER user
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => void;
  register: (email: string, password: string, phone: string) => Promise<void>;
  requestEmailOtp: (email: string) => Promise<void>;
  verifyEmailOtp: (email: string, otp: string) => Promise<void>;
  requestPhoneOtp: (phone: string) => Promise<void>;
  verifyPhoneOtp: (phone: string, otp: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  
  // Derived state - read from /auth/me response ONLY
  isAuthenticated: boolean;
  isFullyVerified: boolean;
}

const UIContext = createContext<UIContextType | undefined>(undefined);

export const UIProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [state, setState] = useState<UIState>({
    isLoading: false,
    isInitialized: false,
    sidebarOpen: false,
    theme: 'light',
    user: null,
  });

  /**
   * Refresh user from /auth/me - SINGLE SOURCE OF TRUTH
   * 
   * THIS IS THE ONLY PLACE USER STATE IS SET
   * Called on mount, tab focus, and after auth mutations
   */
  const refreshUser = useCallback(async (): Promise<void> => {
    try {
      const user = await authApi.getCurrentUser();
      setState(prev => ({ ...prev, user, isInitialized: true }));
    } catch {
      setState(prev => ({ ...prev, user: null, isInitialized: true }));
    }
  }, []);

  // Initialize on mount
  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  // Revalidate on tab focus (browser-level session sync)
  useEffect(() => {
    const handleFocus = () => {
      refreshUser();
    };
    window.addEventListener('focus', handleFocus);
    return () => window.removeEventListener('focus', handleFocus);
  }, [refreshUser]);

  const setLoading = (loading: boolean): void => {
    setState(prev => ({ ...prev, isLoading: loading }));
  };

  const toggleSidebar = (): void => {
    setState(prev => ({ ...prev, sidebarOpen: !prev.sidebarOpen }));
  };

  const toggleTheme = (): void => {
    const newTheme = state.theme === 'light' ? 'dark' : 'light';
    setState(prev => ({ ...prev, theme: newTheme }));
    document.documentElement.classList.toggle('dark', newTheme === 'dark');
  };

  // ============================================================================
  // AUTH ACTIONS - All return void, all hydrate via refreshUser()
  // ============================================================================

  /**
   * Login - stores JWT, then hydrates user from /auth/me
   */
  const login = async (email: string, password: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.login(email, password);
      await refreshUser(); // Hydrate from /auth/me
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  /**
   * Google OAuth - redirects to backend OAuth URL
   */
  const loginWithGoogle = (): void => {
    authApi.initiateGoogleOAuth();
  };

  /**
   * Register - stores JWT, does NOT hydrate (redirect to verify)
   */
  const register = async (email: string, password: string, phone: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.register(email, password, phone);
      // Do NOT refresh - redirect to verification
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const requestEmailOtp = async (email: string): Promise<void> => {
    await authApi.requestEmailOtp(email);
  };

  /**
   * Verify email OTP - then hydrate from /auth/me
   */
  const verifyEmailOtp = async (email: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.verifyEmailOtp(email, otp);
      await refreshUser(); // Revalidate state from /auth/me
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const requestPhoneOtp = async (phone: string): Promise<void> => {
    await authApi.requestPhoneOtp(phone);
  };

  /**
   * Verify phone OTP - then hydrate from /auth/me
   */
  const verifyPhoneOtp = async (phone: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.verifyPhoneOtp(phone, otp);
      await refreshUser(); // Revalidate state from /auth/me
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  /**
   * Logout - clears token and user state
   */
  const logout = async (): Promise<void> => {
    await authApi.logout();
    setState(prev => ({ ...prev, user: null }));
  };

  // Derived state - from /auth/me response ONLY
  const isAuthenticated = !!state.user?.id;
  const isFullyVerified = !!(state.user?.emailVerified && state.user?.phoneVerified);

  return (
    <UIContext.Provider value={{ 
      ...state, 
      setLoading, 
      toggleSidebar, 
      toggleTheme,
      login,
      loginWithGoogle,
      register,
      requestEmailOtp,
      verifyEmailOtp,
      requestPhoneOtp,
      verifyPhoneOtp,
      logout,
      refreshUser,
      isAuthenticated,
      isFullyVerified,
    }}>
      {children}
    </UIContext.Provider>
  );
};

export const useUI = (): UIContextType => {
  const context = useContext(UIContext);
  if (!context) {
    throw new Error('useUI must be used within a UIProvider');
  }
  return context;
};
