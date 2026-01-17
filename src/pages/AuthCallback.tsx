/**
 * OAuth Callback Page
 * 
 * Handles redirect from backend after Google OAuth
 * Backend has already validated auth and issued JWT in URL params
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Loader2, CheckCircle, XCircle } from 'lucide-react';
import { handleOAuthCallback } from '@/api/auth.api';
import { useUI } from '@/context/UIContext';
import AIAvatar from '@/components/AIAvatar';

const AuthCallback: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refreshUser } = useUI();
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const processCallback = async () => {
      // Get token from URL params (backend placed it there after Google auth)
      const token = searchParams.get('token');
      const error = searchParams.get('error');

      if (error) {
        setStatus('error');
        setErrorMessage(decodeURIComponent(error));
        return;
      }

      if (!token) {
        setStatus('error');
        setErrorMessage('No authentication token received');
        return;
      }

      try {
        const user = await handleOAuthCallback(token);
        
        if (!user) {
          setStatus('error');
          setErrorMessage('Failed to verify session');
          return;
        }

        setStatus('success');
        
        // Refresh UI context
        await refreshUser();
        
        // Navigate based on user state
        setTimeout(() => {
          if (!user.emailVerified) {
            navigate('/verify/email', { replace: true });
          } else if (!user.phoneVerified) {
            navigate('/verify/phone', { replace: true });
          } else {
            navigate('/student/profile', { replace: true });
          }
        }, 1000);
      } catch (err) {
        setStatus('error');
        setErrorMessage('Authentication failed. Please try again.');
      }
    };

    processCallback();
  }, [searchParams, navigate, refreshUser]);

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass-strong rounded-3xl p-12 max-w-md w-full text-center"
      >
        <div className="flex justify-center mb-8">
          <AIAvatar 
            state={status === 'processing' ? 'thinking' : 'idle'} 
            size="lg" 
          />
        </div>

        {status === 'processing' && (
          <>
            <Loader2 className="w-12 h-12 text-primary mx-auto mb-4 animate-spin" />
            <h1 className="text-2xl font-bold mb-2">Completing Sign In</h1>
            <p className="text-muted-foreground">
              Verifying your authentication...
            </p>
          </>
        )}

        {status === 'success' && (
          <>
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 200 }}
            >
              <CheckCircle className="w-16 h-16 text-emerald-500 mx-auto mb-4" />
            </motion.div>
            <h1 className="text-2xl font-bold mb-2 text-emerald-500">
              Authentication Successful
            </h1>
            <p className="text-muted-foreground">
              Redirecting to your dashboard...
            </p>
          </>
        )}

        {status === 'error' && (
          <>
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 200 }}
            >
              <XCircle className="w-16 h-16 text-destructive mx-auto mb-4" />
            </motion.div>
            <h1 className="text-2xl font-bold mb-2 text-destructive">
              Authentication Failed
            </h1>
            <p className="text-muted-foreground mb-6">
              {errorMessage}
            </p>
            <button
              onClick={() => navigate('/login', { replace: true })}
              className="text-primary hover:underline"
            >
              Return to Login
            </button>
          </>
        )}
      </motion.div>
    </div>
  );
};

export default AuthCallback;
