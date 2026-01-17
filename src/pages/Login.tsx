// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Mail, Lock, Phone } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import FocusInput from '@/components/FocusInput';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';
import { useUI } from '@/context/UIContext';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login, register, isFullyVerified, user, isAuthenticated } = useUI();
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
    } catch (err) {
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
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
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

            <p className="text-xs text-center text-muted-foreground mt-6 p-3 rounded-lg bg-muted/50">
              ⚠️ FRONTEND FROZEN — Backend integration pending.
            </p>
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
