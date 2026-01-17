// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// This component is deprecated - email/phone verification replaces DigiLocker/Google
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { AlertTriangle, CheckCircle, Mail, Phone, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useUI } from '@/context/UIContext';

const VerificationBanner: React.FC = () => {
  const navigate = useNavigate();
  const { user, isFullyVerified } = useUI();

  if (!user) return null;
  if (isFullyVerified) return null;

  const emailVerified = user.emailVerified;
  const phoneVerified = user.phoneVerified;

  const getNextStep = () => {
    if (!emailVerified) return '/verify/email';
    if (!phoneVerified) return '/verify/phone';
    return null;
  };

  const nextStep = getNextStep();

  return (
    <motion.div
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 mb-6"
    >
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <h3 className="font-semibold text-foreground mb-1">
            Verification Incomplete
          </h3>
          <p className="text-sm text-muted-foreground mb-3">
            Complete all verification steps to access matching features.
          </p>
          
          <div className="flex flex-wrap gap-3 mb-3">
            <div className="flex items-center gap-2">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center ${
                emailVerified 
                  ? 'bg-emerald-500/20 text-emerald-500' 
                  : 'bg-muted text-muted-foreground'
              }`}>
                {emailVerified ? (
                  <CheckCircle className="w-4 h-4" />
                ) : (
                  <Mail className="w-4 h-4" />
                )}
              </div>
              <span className={`text-sm ${emailVerified ? 'text-emerald-500' : 'text-muted-foreground'}`}>
                Email {emailVerified ? '✓' : ''}
              </span>
            </div>
            
            <div className="flex items-center gap-2">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center ${
                phoneVerified 
                  ? 'bg-emerald-500/20 text-emerald-500' 
                  : 'bg-muted text-muted-foreground'
              }`}>
                {phoneVerified ? (
                  <CheckCircle className="w-4 h-4" />
                ) : (
                  <Phone className="w-4 h-4" />
                )}
              </div>
              <span className={`text-sm ${phoneVerified ? 'text-emerald-500' : 'text-muted-foreground'}`}>
                Phone {phoneVerified ? '✓' : ''}
              </span>
            </div>
          </div>

          {nextStep && (
            <Button 
              size="sm" 
              onClick={() => navigate(nextStep)}
              className="gap-2"
            >
              Continue Verification
              <ArrowRight className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default VerificationBanner;
