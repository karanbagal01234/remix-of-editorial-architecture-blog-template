/**
 * API Client - Production Configuration
 * 
 * JWT-ONLY AUTH MODEL:
 * - NO refresh token logic
 * - NO silent refresh
 * - If /auth/me fails → session is invalid
 */

import axios, { AxiosError } from 'axios';
import { toast } from 'sonner';

const AUTH_TOKEN_KEY = 'aura_access_token';

// Validate required environment variable
const apiBaseUrl = import.meta.env.VITE_API_URL;
if (!apiBaseUrl && import.meta.env.PROD) {
  throw new Error('VITE_API_URL environment variable is required for production');
}

const api = axios.create({
  baseURL: apiBaseUrl || '/api',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - attach JWT
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem(AUTH_TOKEN_KEY);
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle 401 (session invalid)
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Session is invalid - clear token and redirect
      localStorage.removeItem(AUTH_TOKEN_KEY);
      
      // Only redirect if not already on login page
      if (!window.location.pathname.includes('/login')) {
        toast.error('Session expired. Please log in again.');
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;
