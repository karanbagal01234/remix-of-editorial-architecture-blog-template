// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Profile Page
 * 
 * Displays and edits student profile information.
 * All data is backend-authoritative.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { User, Mail, Phone, MapPin, FileText, X, Save, CheckCircle, AlertCircle } from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import FocusInput from '@/components/FocusInput';
import AuraGuidance from '@/components/AuraGuidance';
import StudentHeader from '@/components/StudentHeader';
import { useUI } from '@/context/UIContext';
import { updateStudentProfile } from '@/api/student.api';
import { useToast } from '@/hooks/use-toast';
import type { UserLocation } from '@/types/student';
import { Badge } from '@/components/ui/badge';

const StudentProfile: React.FC = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, isFullyVerified, refreshUser } = useUI();
  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [phone, setPhone] = useState(user?.phone || '');
  const [location, setLocation] = useState<UserLocation | null>(user?.location || null);
  const [resume, setResume] = useState(user?.resume || '');
  const [skills, setSkills] = useState<string[]>([...(user?.skills || [])]);
  const [newSkill, setNewSkill] = useState('');
  const [isLocating, setIsLocating] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const handleDetectLocation = () => {
    setIsLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLocation({ lat: pos.coords.latitude, lng: pos.coords.longitude });
        setIsLocating(false);
        toast({ title: 'Location detected!', description: `Lat: ${pos.coords.latitude.toFixed(4)}, Lng: ${pos.coords.longitude.toFixed(4)}` });
      },
      () => {
        setIsLocating(false);
        toast({ title: 'Location error', description: 'Could not detect location', variant: 'destructive' });
      }
    );
  };

  const handleAddSkill = () => {
    if (newSkill.trim() && !skills.includes(newSkill.trim())) {
      setSkills([...skills, newSkill.trim()]);
      setNewSkill('');
    }
  };

  const handleRemoveSkill = (skill: string) => {
    setSkills(skills.filter(s => s !== skill));
  };

  const handleResumeUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setResume(file.name);
      toast({ title: 'Resume uploaded', description: file.name });
    }
  };

  const handleSave = async () => {
    if (!name || !email || !phone || !location) {
      toast({ title: 'Missing fields', description: 'Please fill all required fields', variant: 'destructive' });
      return;
    }

    setIsSaving(true);

    try {
      await updateStudentProfile({ 
        name, 
        email, 
        phone, 
        location, 
        resume, 
        skills, 
        status: 'skills-pending' 
      });
      await refreshUser();
      toast({ title: 'Profile saved!' });
      navigate('/student/skill-extraction');
    } catch (err) {
      toast({ title: 'Save failed', description: 'Please try again', variant: 'destructive' });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <div className="max-w-2xl mx-auto">
        <StudentHeader />
        
        {/* Verification Status Banner */}
        <motion.div 
          className={`mb-6 p-4 rounded-xl border ${isFullyVerified ? 'bg-green-500/10 border-green-500/30' : 'bg-amber-500/10 border-amber-500/30'}`}
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="flex items-center gap-3">
            {isFullyVerified ? (
              <>
                <CheckCircle className="w-5 h-5 text-green-600" />
                <div>
                  <p className="font-medium text-green-700 dark:text-green-400">Fully Verified</p>
                  <p className="text-sm text-muted-foreground">Email and phone verified</p>
                </div>
              </>
            ) : (
              <>
                <AlertCircle className="w-5 h-5 text-amber-600" />
                <div>
                  <p className="font-medium text-amber-700 dark:text-amber-400">Verification Pending</p>
                  <p className="text-sm text-muted-foreground">
                    {!user?.emailVerified && 'Email not verified. '}
                    {!user?.phoneVerified && 'Phone not verified.'}
                  </p>
                </div>
              </>
            )}
          </div>
        </motion.div>
        
        <motion.div className="glass-strong rounded-3xl p-8" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-2xl font-bold mb-2">Complete Your Profile</h1>
          <p className="text-muted-foreground mb-6">Fill in all fields to proceed to skill extraction.</p>
          
          <div className="space-y-6">
            <FocusInput label="Full Name *" icon={<User className="w-5 h-5" />} value={name} onChange={(e) => setName(e.target.value)} placeholder="Your full name" />
            <FocusInput label="Email *" icon={<Mail className="w-5 h-5" />} value={email} onChange={(e) => setEmail(e.target.value)} placeholder="your@email.com" type="email" disabled />
            <FocusInput label="Phone *" icon={<Phone className="w-5 h-5" />} value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="Phone number" disabled />
            
            <div>
              <label className="block text-sm font-medium mb-2">Location *</label>
              <div className="flex gap-2">
                <div className="flex-1 p-3 rounded-lg border border-border bg-muted/50">
                  {location ? `${location.lat.toFixed(4)}, ${location.lng.toFixed(4)}` : 'Not set - click Detect'}
                </div>
                <AnimatedButton onClick={handleDetectLocation} isLoading={isLocating} variant="outline" disabled={isLocating}>
                  <MapPin className="w-4 h-4 mr-2" /> Detect
                </AnimatedButton>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Resume</label>
              <div className="flex gap-2 items-center">
                <input type="file" accept=".pdf,.doc,.docx" onChange={handleResumeUpload} className="hidden" id="resume-upload" />
                <label htmlFor="resume-upload" className="cursor-pointer flex-1 p-3 rounded-lg border border-dashed border-border hover:border-primary transition-colors flex items-center gap-2">
                  <FileText className="w-5 h-5 text-muted-foreground" />
                  <span className="text-muted-foreground">{resume || 'Upload resume (optional)'}</span>
                </label>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Skills</label>
              <div className="flex flex-wrap gap-2 mb-2">
                {skills.length === 0 && (
                  <span className="text-sm text-muted-foreground">No skills added yet</span>
                )}
                {skills.map(skill => (
                  <Badge key={skill} variant="secondary" className="px-3 py-1 flex items-center gap-1">
                    {skill}
                    <button onClick={() => handleRemoveSkill(skill)}><X className="w-3 h-3" /></button>
                  </Badge>
                ))}
              </div>
              <div className="flex gap-2">
                <input value={newSkill} onChange={(e) => setNewSkill(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAddSkill()} placeholder="Add skill" className="flex-1 p-3 rounded-lg border border-border bg-background" />
                <AnimatedButton onClick={handleAddSkill} variant="outline">Add</AnimatedButton>
              </div>
            </div>

            <AnimatedButton onClick={handleSave} className="w-full" size="lg" disabled={!isFullyVerified || isSaving} isLoading={isSaving}>
              <Save className="w-4 h-4 mr-2" /> Save Profile
            </AnimatedButton>
            
            {!isFullyVerified && (
              <p className="text-xs text-center text-muted-foreground">
                Complete email and phone verification to enable saving.
              </p>
            )}
          </div>
        </motion.div>
      </div>
      <AuraGuidance message="Fill in your details so I can find the best matches for you!" />
    </div>
  );
};

export default StudentProfile;
