/**
 * Student Status Page
 * 
 * FRONTEND FROZEN — BACKEND INTEGRATION ONLY
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { CheckCircle, Clock, Sparkles, Play, AlertCircle, Shield } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import AuraGuidance from '@/components/AuraGuidance';
import StudentHeader from '@/components/StudentHeader';
import { useUI } from '@/context/UIContext';
import { runMatchSimulation as runMatchApi } from '@/api/match.api';
import { useToast } from '@/hooks/use-toast';

const Status: React.FC = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, refreshUser } = useUI();
  const [isMatching, setIsMatching] = useState(false);

  const runMatchSimulation = async () => {
    if (!user) return;
    
    setIsMatching(true);
    
    try {
      await runMatchApi();
      await refreshUser();
      toast({ title: 'Match complete!' });
      navigate('/student/result');
    } catch (err) {
      toast({ title: 'Match simulation failed', variant: 'destructive' });
    } finally {
      setIsMatching(false);
    }
  };

  const isSubmitted = user?.status === 'submitted' || user?.status === 'processing';
  const hasResult = user?.matchResult !== null;

  const timeline = [
    { label: 'Application Submitted', done: true, icon: CheckCircle },
    { label: 'Processing', done: hasResult, icon: Clock },
    { label: 'Awaiting Match', done: hasResult, icon: Sparkles },
  ];

  return (
    <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <div className="max-w-2xl mx-auto">
        <StudentHeader />
        
        <motion.div className="glass-strong rounded-3xl p-8" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-2xl font-bold mb-2">Application Status</h1>
          <p className="text-muted-foreground mb-8">Track your application progress</p>
          
          <div className="space-y-4 mb-8">
            {timeline.map((step, i) => (
              <div key={step.label} className="flex items-center gap-4">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${step.done ? 'bg-emerald-500/20 text-emerald-500' : 'bg-muted text-muted-foreground'}`}>
                  <step.icon className="w-5 h-5" />
                </div>
                <span className={step.done ? 'font-medium' : 'text-muted-foreground'}>{step.label}</span>
                {i < timeline.length - 1 && <div className="flex-1 h-px bg-border" />}
              </div>
            ))}
          </div>

          {!isSubmitted && !hasResult && (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-amber-500/10 border border-amber-500/20 mb-6">
              <AlertCircle className="w-5 h-5 text-amber-500" />
              <p className="text-sm text-muted-foreground">
                Your application hasn't been submitted yet. Please complete all previous steps.
              </p>
            </div>
          )}

          {hasResult ? (
            <AnimatedButton onClick={() => navigate('/student/result')} className="w-full" size="lg">
              View Match Result
            </AnimatedButton>
          ) : (
            <AnimatedButton 
              onClick={runMatchSimulation} 
              className="w-full" 
              size="lg" 
              isLoading={isMatching} 
              disabled={!isSubmitted || isMatching}
            >
              <Play className="w-4 h-4 mr-2" /> Run Match Simulation
            </AnimatedButton>
          )}
          
          {!hasResult && isSubmitted && (
            <p className="text-xs text-center text-muted-foreground mt-4">
              Click the button above to simulate the AI matching process
            </p>
          )}

          {/* System Notice */}
          <div className="mt-6 pt-4 border-t border-border">
            <div className="flex items-center justify-center gap-2 text-muted-foreground">
              <Shield className="w-4 h-4" />
              <p className="text-xs">
                Status is system generated. Match outcomes cannot be influenced by students.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
      <AuraGuidance message={hasResult ? "Your match result is ready! Click to view." : isSubmitted ? "Click the button to simulate the matching process!" : "Complete all previous steps to run the match simulation."} />
    </div>
  );
};

export default Status;