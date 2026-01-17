/**
 * Login Page - Email/OTP + Google OAuth
 * 
 * All auth flows result in identical session state via /auth/me
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Mail, Lock, Phone } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import FocusInput from '@/components/FocusInput';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';
import { useUI } from '@/context/UIContext';
import { Button } from '@/components/ui/button';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login, loginWithGoogle, register, isFullyVerified, isAuthenticated } = useUI();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      if (isFullyVerified) {
        navigate('/student/profile', { replace: true });
      } else {
        navigate('/verify/email', { replace: true });
      }
    }
  }, [isAuthenticated, isFullyVerified, navigate]);

  const handleLogin = async () => {
    if (!email || !password) {
      setError('Please enter email and password');
      return;
    }
    
    setIsLoading(true);
    setError('');
    
    try {
      await login(email, password);
      // Navigation handled by useEffect
    } catch {
      setError('Invalid credentials. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!email || !password || !phone) {
      setError('Please fill all fields');
      return;
    }
    
    setIsLoading(true);
    setError('');
    
    try {
      await register(email, password, phone);
      navigate('/verify/email');
    } catch {
      setError('Registration failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    loginWithGoogle();
  };

  const getAuraMessage = () => {
    if (mode === 'register') {
      return "Create your account with email and password. You'll verify your email and phone next.";
    }
    return "Sign in to continue your journey with Aura-Match.";
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-background via-muted/30 to-background">
        <div className="absolute top-20 left-20 w-72 h-72 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute bottom-20 right-20 w-96 h-96 rounded-full bg-secondary/10 blur-3xl" />
      </div>

      <motion.div
        className="relative glass-strong rounded-3xl p-8 md:p-12 w-full max-w-md"
        initial={{ opacity: 0, y: 30, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5 }}
      >
        <div className="flex justify-center mb-8">
          <AIAvatar state={isLoading ? 'thinking' : 'idle'} size="lg" />
        </div>

        <h1 className="text-2xl md:text-3xl font-bold text-center mb-2">
          Welcome to <span className="gradient-text">Aura-Match</span>
        </h1>
        <p className="text-muted-foreground text-center mb-8">
          {mode === 'login' ? 'Sign in to continue' : 'Create your account'}
        </p>

        <AnimatePresence mode="wait">
          <motion.div key="auth-form" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            {/* Google OAuth Button */}
            <Button
              type="button"
              variant="outline"
              className="w-full mb-6 flex items-center justify-center gap-3 h-12"
              onClick={handleGoogleLogin}
              disabled={isLoading}
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>
              Continue with Google
            </Button>

            <div className="relative mb-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-border"></div>
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">Or continue with email</span>
              </div>
            </div>

            <FocusInput
              label="Email Address"
              icon={<Mail className="w-5 h-5" />}
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type="email"
            />

            <div className="mt-4">
              <FocusInput
                label="Password"
                icon={<Lock className="w-5 h-5" />}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
              />
            </div>

            {mode === 'register' && (
              <div className="mt-4">
                <FocusInput
                  label="Phone Number"
                  icon={<Phone className="w-5 h-5" />}
                  placeholder="Enter your phone number"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                />
              </div>
            )}

            {error && (
              <p className="text-sm text-destructive mt-4">{error}</p>
            )}

            <AnimatedButton
              onClick={mode === 'login' ? handleLogin : handleRegister}
              className="w-full mt-6"
              size="lg"
              isLoading={isLoading}
              disabled={isLoading}
            >
              {mode === 'login' ? 'Sign In' : 'Create Account'}
            </AnimatedButton>

            <button
              onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
              className="w-full mt-4 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              {mode === 'login' ? "Don't have an account? Register" : 'Already have an account? Sign In'}
            </button>
          </motion.div>
        </AnimatePresence>

        <Link to="/" className="block text-center mt-6 text-sm text-muted-foreground hover:text-foreground transition-colors">
          ← Back to Home
        </Link>
      </motion.div>

      <AuraGuidance message={getAuraMessage()} />
    </div>
  );
};

export default Login;
