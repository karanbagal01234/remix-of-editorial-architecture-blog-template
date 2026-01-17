// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Company Email OTP Verification Page
 * 
 * Sends OTP to company's email and verifies it.
 * All verification logic is backend-authoritative.
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Mail, ArrowRight, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';
import { useCompany } from '@/context/CompanyContext';
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp';

const CompanyVerifyEmail: React.FC = () => {
  const navigate = useNavigate();
  const { company, requestEmailOtp, verifyEmailOtp, isVerified, isLoading } = useCompany();
  const [otp, setOtp] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState('');
  const [otpSent, setOtpSent] = useState(false);

  // Redirect if already verified
  useEffect(() => {
    if (isVerified) {
      navigate('/company/profile', { replace: true });
    }
  }, [isVerified, navigate]);

  // Redirect if not logged in
  useEffect(() => {
    if (!company) {
      navigate('/company/login', { replace: true });
    }
  }, [company, navigate]);

  const handleSendOtp = async () => {
    if (!company?.email) return;
    
    setIsSending(true);
    setError('');
    
    try {
      await requestEmailOtp(company.email);
      setOtpSent(true);
    } catch (err) {
      setError('Failed to send OTP. Please try again.');
    } finally {
      setIsSending(false);
    }
  };

  const handleVerify = async () => {
    if (otp.length !== 6 || !company?.email) return;
    
    setError('');
    
    try {
      await verifyEmailOtp(company.email, otp);
      navigate('/company/profile');
    } catch (err) {
      setError('Invalid OTP. Please try again.');
      setOtp('');
    }
  };

  if (!company) return null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <div className="bg-card border border-border rounded-2xl shadow-xl p-8">
          <div className="text-center mb-8">
            <div className="flex justify-center mb-4">
              <AIAvatar size="lg" state={isLoading ? 'thinking' : 'idle'} />
            </div>
            <div className="w-16 h-16 rounded-2xl gradient-bg flex items-center justify-center mx-auto mb-4">
              <Mail className="w-8 h-8 text-primary-foreground" />
            </div>
            <h1 className="text-2xl font-bold text-foreground mb-2">
              Verify Your Email
            </h1>
            <p className="text-muted-foreground">
              {otpSent 
                ? `We've sent a 6-digit code to ${company.email}`
                : `We'll send a verification code to ${company.email}`
              }
            </p>
          </div>

          {!otpSent ? (
            <Button
              onClick={handleSendOtp}
              className="w-full"
              size="lg"
              disabled={isSending}
            >
              {isSending ? 'Sending...' : 'Send Verification Code'}
              <Mail className="w-4 h-4 ml-2" />
            </Button>
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

              <Button
                onClick={handleVerify}
                className="w-full"
                size="lg"
                disabled={isLoading || otp.length !== 6}
              >
                {isLoading ? 'Verifying...' : 'Verify Email'}
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>

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

          <div className="mt-6 text-center">
            <Link
              to="/company/login"
              className="text-sm text-muted-foreground hover:text-primary transition-colors"
            >
              ← Back to Login
            </Link>
          </div>
        </div>

        <div className="mt-6">
          <AuraGuidance
            message="Check your email for the verification code. This helps us verify your company identity."
          />
        </div>
      </motion.div>
    </div>
  );
};

export default CompanyVerifyEmail;
