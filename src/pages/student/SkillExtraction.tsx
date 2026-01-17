/**
 * Student Skill Extraction Page
 * 
 * FRONTEND FROZEN — BACKEND INTEGRATION ONLY
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Sparkles, X, Plus, ArrowRight } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import LoadingSkeleton from '@/components/LoadingSkeleton';
import AuraGuidance from '@/components/AuraGuidance';
import StudentHeader from '@/components/StudentHeader';
import { extractSkillsFromResume, confirmSkills } from '@/api/student.api';
import { useUI } from '@/context/UIContext';
import { useToast } from '@/hooks/use-toast';

const SkillExtraction: React.FC = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { refreshUser } = useUI();
  const [isExtracting, setIsExtracting] = useState(true);
  const [isConfirming, setIsConfirming] = useState(false);
  const [skills, setSkills] = useState<string[]>([]);
  const [newSkill, setNewSkill] = useState('');

  useEffect(() => {
    const loadSkills = async () => {
      try {
        // FRONTEND FROZEN — resumeId 'current' tells backend to use active resume
        const extractedSkills = await extractSkillsFromResume('current');
        setSkills(extractedSkills);
      } catch (err) {
        toast({ title: 'Error extracting skills', variant: 'destructive' });
      } finally {
        setIsExtracting(false);
      }
    };
    
    loadSkills();
  }, [toast]);

  const handleRemove = (skill: string) => setSkills(skills.filter(s => s !== skill));
  
  const handleAdd = () => {
    if (newSkill.trim() && !skills.includes(newSkill.trim())) {
      setSkills([...skills, newSkill.trim()]);
      setNewSkill('');
    }
  };

  const handleConfirm = async () => {
    if (skills.length === 0) {
      toast({ title: 'Add at least one skill', variant: 'destructive' });
      return;
    }
    
    setIsConfirming(true);
    
    try {
      await confirmSkills(skills);
      await refreshUser();
      toast({ title: 'Skills confirmed!' });
      navigate('/student/preferences');
    } catch (err) {
      toast({ title: 'Error saving skills', variant: 'destructive' });
    } finally {
      setIsConfirming(false);
    }
  };

  return (
    <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <div className="max-w-2xl mx-auto">
        <StudentHeader />
        
        <motion.div className="glass-strong rounded-3xl p-8" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl gradient-bg flex items-center justify-center">
              <Sparkles className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Skill Extraction</h1>
              <p className="text-muted-foreground text-sm">AI-powered analysis of your resume</p>
            </div>
          </div>

          {isExtracting ? (
            <div className="space-y-4">
              <p className="text-center text-muted-foreground">Analyzing your resume...</p>
              <LoadingSkeleton lines={4} />
            </div>
          ) : (
            <>
              <p className="text-muted-foreground mb-4">Review and edit the skills we found:</p>
              
              {skills.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <p>No skills extracted yet. Add some skills below!</p>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2 mb-6">
                  {skills.map(skill => (
                    <motion.span key={skill} className="px-4 py-2 rounded-full bg-primary/10 text-primary flex items-center gap-2" initial={{ scale: 0 }} animate={{ scale: 1 }}>
                      {skill}
                      <button onClick={() => handleRemove(skill)} disabled={isConfirming}><X className="w-4 h-4" /></button>
                    </motion.span>
                  ))}
                </div>
              )}
              
              <div className="flex gap-2 mb-6">
                <input 
                  value={newSkill} 
                  onChange={(e) => setNewSkill(e.target.value)} 
                  onKeyDown={(e) => e.key === 'Enter' && handleAdd()} 
                  placeholder="Add another skill" 
                  className="flex-1 p-3 rounded-lg border border-border bg-background"
                  disabled={isConfirming}
                />
                <AnimatedButton onClick={handleAdd} variant="outline" disabled={isConfirming}><Plus className="w-4 h-4" /></AnimatedButton>
              </div>
              <AnimatedButton onClick={handleConfirm} className="w-full" size="lg" isLoading={isConfirming} disabled={isConfirming || skills.length === 0}>
                Confirm Skills <ArrowRight className="w-4 h-4 ml-2" />
              </AnimatedButton>
            </>
          )}
        </motion.div>
      </div>
      <AuraGuidance message={isExtracting ? "I'm reading through your resume to find your strengths..." : skills.length === 0 ? "Add some skills to continue!" : "These are the skills I found. Feel free to add or remove any!"} />
    </div>
  );
};

export default SkillExtraction;