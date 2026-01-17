// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import axios from 'axios';

// Pre-configured axios instance for backend API
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth token
api.interceptors.request.use(
  (config) => {
    // Get token from localStorage - only auth tokens stored locally
    const token = localStorage.getItem('aura_access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // Company token fallback
    const companyToken = localStorage.getItem('aura_company_token');
    if (!token && companyToken) {
      config.headers.Authorization = `Bearer ${companyToken}`;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Handle 401 - token expired
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Try to refresh token
      const refreshToken = localStorage.getItem('aura_refresh_token');
      if (refreshToken) {
        try {
          const response = await axios.post(`${api.defaults.baseURL}/auth/refresh`, {
            refreshToken,
          });
          const { accessToken, refreshToken: newRefresh } = response.data;
          localStorage.setItem('aura_access_token', accessToken);
          if (newRefresh) {
            localStorage.setItem('aura_refresh_token', newRefresh);
          }
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh failed - clear tokens and redirect
          localStorage.removeItem('aura_access_token');
          localStorage.removeItem('aura_refresh_token');
          localStorage.removeItem('aura_company_token');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }
      
      // No refresh token - redirect to login
      localStorage.removeItem('aura_access_token');
      localStorage.removeItem('aura_company_token');
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);

export default api;
