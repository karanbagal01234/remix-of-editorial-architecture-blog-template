// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Email OTP Verification Page
 * 
 * Sends OTP to user's email and verifies it.
 * All verification logic is backend-authoritative.
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Mail, ArrowRight, RefreshCw } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';
import { useUI } from '@/context/UIContext';
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp';

const VerifyEmail: React.FC = () => {
  const navigate = useNavigate();
  const { user, requestEmailOtp, verifyEmailOtp, isFullyVerified } = useUI();
  const [otp, setOtp] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState('');
  const [otpSent, setOtpSent] = useState(false);

  // Redirect if already fully verified
  useEffect(() => {
    if (isFullyVerified) {
      navigate('/student/profile', { replace: true });
    } else if (user?.emailVerified && !user?.phoneVerified) {
      navigate('/verify/phone', { replace: true });
    }
  }, [isFullyVerified, user, navigate]);

  // Redirect if not logged in
  useEffect(() => {
    if (!user) {
      navigate('/login', { replace: true });
    }
  }, [user, navigate]);

  const handleSendOtp = async () => {
    if (!user?.email) return;
    
    setIsSending(true);
    setError('');
    
    try {
      await requestEmailOtp(user.email);
      setOtpSent(true);
    } catch (err) {
      setError('Failed to send OTP. Please try again.');
    } finally {
      setIsSending(false);
    }
  };

  const handleVerify = async () => {
    if (otp.length !== 6 || !user?.email) return;
    
    setIsLoading(true);
    setError('');
    
    try {
      await verifyEmailOtp(user.email, otp);
      // After email verification, check if phone needs verification
      if (!user.phoneVerified) {
        navigate('/verify/phone');
      } else {
        navigate('/student/profile');
      }
    } catch (err) {
      setError('Invalid OTP. Please try again.');
      setOtp('');
    } finally {
      setIsLoading(false);
    }
  };

  if (!user) return null;

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

        <div className="flex justify-center mb-6">
          <div className="w-16 h-16 rounded-2xl gradient-bg flex items-center justify-center">
            <Mail className="w-8 h-8 text-primary-foreground" />
          </div>
        </div>

        <h1 className="text-2xl font-bold text-center mb-2">Verify Your Email</h1>
        <p className="text-muted-foreground text-center mb-6">
          {otpSent 
            ? `We've sent a 6-digit code to ${user.email}`
            : `We'll send a verification code to ${user.email}`
          }
        </p>

        {!otpSent ? (
          <AnimatedButton
            onClick={handleSendOtp}
            className="w-full"
            size="lg"
            isLoading={isSending}
            disabled={isSending}
          >
            Send Verification Code
            <Mail className="w-4 h-4 ml-2" />
          </AnimatedButton>
        ) : (
          <div className="space-y-6">
            <div className="flex justify-center">
              <InputOTP
                maxLength={6}
                value={otp}
                onChange={setOtp}
              >
                <InputOTPGroup>
                  <InputOTPSlot index={0} />
                  <InputOTPSlot index={1} />
                  <InputOTPSlot index={2} />
                  <InputOTPSlot index={3} />
                  <InputOTPSlot index={4} />
                  <InputOTPSlot index={5} />
                </InputOTPGroup>
              </InputOTP>
            </div>

            {error && (
              <p className="text-sm text-destructive text-center">{error}</p>
            )}

            <AnimatedButton
              onClick={handleVerify}
              className="w-full"
              size="lg"
              isLoading={isLoading}
              disabled={isLoading || otp.length !== 6}
            >
              Verify Email
              <ArrowRight className="w-4 h-4 ml-2" />
            </AnimatedButton>

            <button
              onClick={handleSendOtp}
              disabled={isSending}
              className="w-full flex items-center justify-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${isSending ? 'animate-spin' : ''}`} />
              Resend Code
            </button>
          </div>
        )}

        <p className="text-xs text-center text-muted-foreground mt-6 p-3 rounded-lg bg-muted/50">
          ⚠️ FRONTEND FROZEN — Backend integration pending.
        </p>

        <Link to="/login" className="block text-center mt-6 text-sm text-muted-foreground hover:text-foreground transition-colors">
          ← Back to Login
        </Link>
      </motion.div>

      <AuraGuidance message="Check your email for the verification code. This helps us keep your account secure!" />
    </div>
  );
};

export default VerifyEmail;
