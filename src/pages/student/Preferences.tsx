/**
 * Student Preferences Page
 * 
 * FRONTEND FROZEN — BACKEND INTEGRATION ONLY
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Settings, ArrowRight } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import AuraGuidance from '@/components/AuraGuidance';
import StudentHeader from '@/components/StudentHeader';
import { useUI } from '@/context/UIContext';
import { updatePreferences } from '@/api/student.api';
import { useToast } from '@/hooks/use-toast';
import domainsData from '@/data/domains.json';

const Preferences: React.FC = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, isFullyVerified, refreshUser } = useUI();
  const [domains, setDomains] = useState<string[]>(user?.preferences?.domains || []);
  const [workStyle, setWorkStyle] = useState<'remote' | 'hybrid' | 'onsite'>(user?.preferences?.workStyle || 'hybrid');
  const [distance, setDistance] = useState(user?.preferences?.distance || 100);
  const [stipend, setStipend] = useState(user?.preferences?.stipend || 0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const toggleDomain = (id: string) => {
    setDomains(domains.includes(id) ? domains.filter(d => d !== id) : [...domains, id]);
  };

  const handleSubmit = async () => {
    if (!isFullyVerified) {
      toast({ title: 'Verification required', description: 'Complete both verifications first', variant: 'destructive' });
      return;
    }
    if (domains.length === 0) {
      toast({ title: 'Select domains', description: 'Choose at least one preferred domain', variant: 'destructive' });
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      await updatePreferences({ domains, workStyle, distance, stipend });
      await refreshUser();
      toast({ title: 'Application submitted!' });
      navigate('/student/status');
    } catch (err) {
      toast({ title: 'Submission failed', description: 'Please try again', variant: 'destructive' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <div className="max-w-2xl mx-auto">
        <StudentHeader />
        
        <motion.div className="glass-strong rounded-3xl p-8" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl gradient-bg flex items-center justify-center">
              <Settings className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Your Preferences</h1>
              <p className="text-muted-foreground text-sm">Tell us what you're looking for</p>
            </div>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium mb-3">Preferred Domains *</label>
              <div className="flex flex-wrap gap-2">
                {domainsData.map(domain => (
                  <button 
                    key={domain.id} 
                    onClick={() => toggleDomain(domain.id)} 
                    className={`px-4 py-2 rounded-full text-sm transition-all ${domains.includes(domain.id) ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-muted/80'}`}
                    disabled={isSubmitting}
                  >
                    {domain.name}
                  </button>
                ))}
              </div>
              {domains.length === 0 && (
                <p className="text-xs text-muted-foreground mt-2">Select at least one domain</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium mb-3">Work Style</label>
              <div className="flex gap-2">
                {(['remote', 'hybrid', 'onsite'] as const).map(style => (
                  <button 
                    key={style} 
                    onClick={() => setWorkStyle(style)} 
                    className={`flex-1 py-3 rounded-lg capitalize transition-all ${workStyle === style ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-muted/80'}`}
                    disabled={isSubmitting}
                  >
                    {style}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-3">Distance Willing: {distance} km</label>
              <input 
                type="range" 
                min="50" 
                max="200" 
                value={distance} 
                onChange={(e) => setDistance(Number(e.target.value))} 
                className="w-full accent-primary"
                disabled={isSubmitting}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-3">Expected Stipend (optional): ₹{stipend.toLocaleString()}/month</label>
              <input 
                type="range" 
                min="0" 
                max="50000" 
                step="5000" 
                value={stipend} 
                onChange={(e) => setStipend(Number(e.target.value))} 
                className="w-full accent-primary"
                disabled={isSubmitting}
              />
            </div>

            <AnimatedButton 
              onClick={handleSubmit} 
              className="w-full" 
              size="lg" 
              disabled={!isFullyVerified || isSubmitting || domains.length === 0}
              isLoading={isSubmitting}
            >
              Submit Application <ArrowRight className="w-4 h-4 ml-2" />
            </AnimatedButton>
          </div>
        </motion.div>
      </div>
      <AuraGuidance message="Tell me what you're looking for, and I'll find the perfect match!" />
    </div>
  );
};

export default Preferences;