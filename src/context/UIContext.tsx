// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * UIContext - Single source of truth for UI state
 * 
 * BACKEND AUTHORITY MODEL:
 * - All user data comes from backend
 * - Context NEVER computes verification status
 * - Context NEVER stores domain data
 * - On refresh: revalidate from backend
 * - After mutations: refetch state
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
  
  // Auth actions - API-driven
  login: (email: string, password: string) => Promise<UserData>;
  register: (email: string, password: string, phone: string) => Promise<void>;
  requestEmailOtp: (email: string) => Promise<void>;
  verifyEmailOtp: (email: string, otp: string) => Promise<void>;
  requestPhoneOtp: (phone: string) => Promise<void>;
  verifyPhoneOtp: (phone: string, otp: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  
  // Derived state - read from backend response
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
   * Refresh user from backend - SINGLE SOURCE OF TRUTH
   * Called on mount, tab focus, and after mutations
   */
  const refreshUser = useCallback(async (): Promise<void> => {
    try {
      const user = await authApi.getCurrentUser();
      setState(prev => ({ ...prev, user, isInitialized: true }));
    } catch (error) {
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
  // AUTH ACTIONS - All backend-authoritative
  // ============================================================================

  const login = async (email: string, password: string): Promise<UserData> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      const result = await authApi.login(email, password);
      setState(prev => ({ ...prev, user: result.user, isLoading: false }));
      return result.user;
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const register = async (email: string, password: string, phone: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.register(email, password, phone);
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const requestEmailOtp = async (email: string): Promise<void> => {
    await authApi.requestEmailOtp(email);
  };

  const verifyEmailOtp = async (email: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.verifyEmailOtp(email, otp);
      await refreshUser(); // Revalidate state from backend
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const requestPhoneOtp = async (phone: string): Promise<void> => {
    await authApi.requestPhoneOtp(phone);
  };

  const verifyPhoneOtp = async (phone: string, otp: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));
    try {
      await authApi.verifyPhoneOtp(phone, otp);
      await refreshUser(); // Revalidate state from backend
      setState(prev => ({ ...prev, isLoading: false }));
    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      throw error;
    }
  };

  const logout = async (): Promise<void> => {
    await authApi.logout();
    setState(prev => ({ ...prev, user: null }));
  };

  // Derived state - from backend response ONLY
  const isAuthenticated = !!state.user?.token;
  const isFullyVerified = !!(state.user?.emailVerified && state.user?.phoneVerified);

  return (
    <UIContext.Provider value={{ 
      ...state, 
      setLoading, 
      toggleSidebar, 
      toggleTheme,
      login,
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
