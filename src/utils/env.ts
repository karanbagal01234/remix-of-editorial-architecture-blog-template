/**
 * Environment Configuration - Fail Fast
 * 
 * RULES:
 * - NO hardcoded URLs
 * - NO localhost assumptions
 * - NO silent fallbacks
 * - App MUST fail fast if env missing in production
 */

interface EnvConfig {
  API_URL: string;
  IS_PRODUCTION: boolean;
  APP_NAME: string;
}

const validateEnv = (): EnvConfig => {
  const isProd = import.meta.env.PROD;
  const apiUrl = import.meta.env.VITE_API_URL;
  
  // Fail fast in production if API URL is not configured
  if (isProd && !apiUrl) {
    const errorMessage = 'FATAL: VITE_API_URL environment variable is required for production deployment';
    console.error(errorMessage);
    throw new Error(errorMessage);
  }
  
  return {
    API_URL: apiUrl || '/api', // Only fallback in development
    IS_PRODUCTION: isProd,
    APP_NAME: 'Aura-Match',
  };
};

// Validate on module load
export const ENV = validateEnv();

/**
 * Get API base URL
 * Returns configured URL or throws in production if not set
 */
export const getApiUrl = (): string => {
  return ENV.API_URL;
};

/**
 * Check if running in production mode
 */
export const isProduction = (): boolean => {
  return ENV.IS_PRODUCTION;
};

export default ENV;
