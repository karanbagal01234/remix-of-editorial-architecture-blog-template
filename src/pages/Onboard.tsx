// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, ArrowRight, FileText, Shield, Sparkles } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';

const steps = [
  {
    id: 1,
    title: 'Welcome to Aura-Match',
    description: "I'm Aura, your AI-powered career matching assistant. I'll help you find the perfect internship opportunity tailored to your skills and preferences.",
    icon: Sparkles,
  },
  {
    id: 2,
    title: 'What We Need From You',
    description: 'To match you with the best opportunities, we\'ll need:',
    icon: FileText,
    items: [
      'Your verified email address',
      'Your verified phone number',
      'Your resume and skills',
      'Your work preferences',
    ],
  },
  {
    id: 3,
    title: 'Eligibility Confirmation',
    description: 'Please confirm that you meet the following criteria:',
    icon: Shield,
    checkbox: true,
    checkboxText: 'I am a student currently enrolled in an educational institution and I consent to share my verified credentials for matching purposes.',
  },
];

const auraMessages = [
  "Hello! I'm so excited to meet you. Let's start your journey to finding the perfect opportunity!",
  "Don't worry, your data is secure with us. We only use it to find you the best matches!",
  "Almost there! Just confirm your eligibility and we'll get you started.",
];

const Onboard: React.FC = () => {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);
  const [isEligible, setIsEligible] = useState(false);

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      if (isEligible) {
        navigate('/login');
      }
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const step = steps[currentStep];
  const Icon = step.icon;

  return (
    <div className="min-h-screen flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-background via-muted/30 to-background">
        <div className="absolute top-20 left-20 w-72 h-72 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute bottom-20 right-20 w-96 h-96 rounded-full bg-secondary/10 blur-3xl" />
      </div>

      {/* Progress bar */}
      <div className="fixed top-0 left-0 right-0 h-1 bg-muted z-50">
        <motion.div
          className="h-full bg-primary"
          initial={{ width: '0%' }}
          animate={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>

      {/* Main Card */}
      <motion.div
        className="relative glass-strong rounded-3xl p-8 md:p-12 w-full max-w-lg"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
      >
        {/* Step indicator */}
        <div className="flex justify-center gap-2 mb-8">
          {steps.map((_, index) => (
            <motion.div
              key={index}
              className={`h-2 rounded-full transition-all ${
                index === currentStep
                  ? 'w-8 bg-primary'
                  : index < currentStep
                  ? 'w-2 bg-primary/50'
                  : 'w-2 bg-muted'
              }`}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: index * 0.1 }}
            />
          ))}
        </div>

        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
          >
            {/* Icon */}
            <div className="flex justify-center mb-6">
              <div className="w-16 h-16 rounded-2xl gradient-bg flex items-center justify-center">
                <Icon className="w-8 h-8 text-primary-foreground" />
              </div>
            </div>

            {/* Content */}
            <h2 className="text-2xl font-bold text-center mb-4">{step.title}</h2>
            <p className="text-muted-foreground text-center mb-6">{step.description}</p>

            {/* Items list */}
            {step.items && (
              <ul className="space-y-3 mb-6">
                {step.items.map((item, index) => (
                  <motion.li
                    key={index}
                    className="flex items-center gap-3 p-3 rounded-lg bg-muted/50"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0" />
                    <span className="text-sm">{item}</span>
                  </motion.li>
                ))}
              </ul>
            )}

            {/* Checkbox */}
            {step.checkbox && (
              <label className="flex items-start gap-3 p-4 rounded-xl border border-border hover:border-primary/50 transition-colors cursor-pointer mb-6">
                <input
                  type="checkbox"
                  checked={isEligible}
                  onChange={(e) => setIsEligible(e.target.checked)}
                  className="w-5 h-5 rounded border-border text-primary focus:ring-primary mt-0.5"
                />
                <span className="text-sm text-muted-foreground">{step.checkboxText}</span>
              </label>
            )}

            {/* Buttons */}
            <div className="flex gap-4">
              {currentStep > 0 && (
                <AnimatedButton variant="outline" onClick={handleBack} className="flex-1">
                  Back
                </AnimatedButton>
              )}
              <AnimatedButton
                onClick={handleNext}
                className="flex-1"
                disabled={step.checkbox && !isEligible}
              >
                {currentStep === steps.length - 1 ? 'Get Started' : 'Continue'}
                <ArrowRight className="w-4 h-4 ml-2" />
              </AnimatedButton>
            </div>
          </motion.div>
        </AnimatePresence>

        {/* Skip link */}
        <Link
          to="/"
          className="block text-center mt-6 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          ← Back to Home
        </Link>
      </motion.div>

      {/* Aura Guidance */}
      <AuraGuidance message={auraMessages[currentStep]} />
    </div>
  );
};

export default Onboard;
