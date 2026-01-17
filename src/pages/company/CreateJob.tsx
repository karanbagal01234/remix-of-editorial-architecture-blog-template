// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Create Job Page
 * 
 * BACKEND AUTHORITY MODEL:
 * - Company submits raw JD text
 * - Backend performs AI/NLP extraction
 * - Frontend displays backend-provided suggestions
 * - NO frontend AI, regex, or heuristics
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Briefcase, MapPin, Users, IndianRupee, Gift, X, Plus, Sparkles, FileText, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import CompanyHeader from '@/components/CompanyHeader';
import AuraGuidance from '@/components/AuraGuidance';
import { useCompany } from '@/context/CompanyContext';
import type { CreateJobInput } from '@/types/company';
import api from '@/utils/api';

// ============= TYPES =============
interface JDAnalysisResult {
  title: string;
  skills: string[];
  location: string;
  intake: number;
  stipend?: number;
  perks?: string;
}

// ============= AI SUGGESTED HINT COMPONENT =============
const AISuggestedHint: React.FC<{ show: boolean }> = ({ show }) => {
  if (!show) return null;
  return (
    <span className="inline-flex items-center gap-1 ml-2 text-xs text-primary/80">
      <Sparkles className="w-3 h-3" />
      AI suggested
    </span>
  );
};

// ============= MAIN COMPONENT =============
const CreateJob: React.FC = () => {
  const navigate = useNavigate();
  const { createJob, processJob, isLoading } = useCompany();

  // JD Analysis state
  const [jobDescription, setJobDescription] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [hasAnalyzed, setHasAnalyzed] = useState(false);

  // Form fields with AI suggestion tracking
  const [title, setTitle] = useState('');
  const [titleSuggested, setTitleSuggested] = useState(false);
  
  const [skillInput, setSkillInput] = useState('');
  const [skills, setSkills] = useState<string[]>([]);
  const [skillsSuggested, setSkillsSuggested] = useState(false);
  
  const [locationLabel, setLocationLabel] = useState('');
  const [locationSuggested, setLocationSuggested] = useState(false);
  
  const [intake, setIntake] = useState('');
  const [intakeSuggested, setIntakeSuggested] = useState(false);
  
  const [stipend, setStipend] = useState('');
  const [stipendSuggested, setStipendSuggested] = useState(false);
  
  const [perks, setPerks] = useState('');
  const [perksSuggested, setPerksSuggested] = useState(false);
  
  const [error, setError] = useState('');

  /**
   * BACKEND-DRIVEN JD ANALYSIS
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   * Frontend sends raw JD text, backend returns extracted fields.
   * NO frontend regex, keyword matching, or heuristics.
   */
  const handleAnalyzeJD = async () => {
    if (jobDescription.length < 100) {
      setError('Please enter a more detailed job description (at least 100 characters)');
      return;
    }

    setError('');
    setIsAnalyzing(true);

    try {
      // BACKEND API CALL - All extraction logic is backend-owned
      const response = await api.post<JDAnalysisResult>('/company/jobs/analyze-jd', {
        jobDescription: jobDescription.trim()
      });
      
      const result = response.data;

      // Auto-fill fields from backend response
      if (result.title) {
        setTitle(result.title);
        setTitleSuggested(true);
      }
      if (result.skills && result.skills.length > 0) {
        setSkills(result.skills);
        setSkillsSuggested(true);
      }
      if (result.location) {
        setLocationLabel(result.location);
        setLocationSuggested(true);
      }
      if (result.intake) {
        setIntake(result.intake.toString());
        setIntakeSuggested(true);
      }
      if (result.stipend) {
        setStipend(result.stipend.toString());
        setStipendSuggested(true);
      }
      if (result.perks) {
        setPerks(result.perks);
        setPerksSuggested(true);
      }

      setHasAnalyzed(true);
    } catch {
      setError('Failed to analyze job description. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAddSkill = () => {
    const trimmed = skillInput.trim();
    if (trimmed && !skills.includes(trimmed)) {
      setSkills([...skills, trimmed]);
      setSkillInput('');
      setSkillsSuggested(false);
    }
  };

  const handleSkillKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddSkill();
    }
  };

  const handleRemoveSkill = (skill: string) => {
    setSkills(skills.filter(s => s !== skill));
    if (skills.length <= 1) setSkillsSuggested(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!jobDescription.trim() || jobDescription.length < 100) {
      setError('A detailed job description is required (at least 100 characters)');
      return;
    }

    if (!title.trim()) {
      setError('Job title is required');
      return;
    }

    if (skills.length === 0) {
      setError('At least one skill is required');
      return;
    }

    if (!locationLabel.trim()) {
      setError('Location is required');
      return;
    }

    const intakeNum = parseInt(intake, 10);
    if (isNaN(intakeNum) || intakeNum < 1) {
      setError('Intake capacity must be at least 1');
      return;
    }

    try {
      // Location coordinates are backend-resolved from label
      // Frontend sends label only, backend geocodes
      const jobData: CreateJobInput = {
        title: title.trim(),
        requiredSkills: skills,
        location: {
          lat: 0, // BACKEND AUTHORITY REQUIRED - Backend will geocode
          lng: 0, // BACKEND AUTHORITY REQUIRED - Backend will geocode
          label: locationLabel.trim(),
        },
        intake: intakeNum,
        stipend: stipend ? parseInt(stipend, 10) : undefined,
        perks: perks.trim() || undefined,
        originalJD: jobDescription.trim(),
      };

      const job = await createJob(jobData);
      await processJob(job.id);
      navigate('/company/jobs/status');
    } catch {
      setError('Failed to create job. Please try again.');
    }
  };

  const jdCharCount = jobDescription.length;
  const isJDValid = jdCharCount >= 100 && jdCharCount <= 5000;

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <CompanyHeader title="Create Job Posting" />

      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="bg-card border border-border rounded-2xl shadow-lg p-8"
        >
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-foreground mb-2">
              Define Your Requirements
            </h1>
            <p className="text-muted-foreground">
              Paste your job description and let our AI extract the key details.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* JD Textarea - PRIMARY INPUT */}
            <div className="space-y-2">
              <Label htmlFor="jd" className="flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Paste Job Description *
              </Label>
              <Textarea
                id="jd"
                placeholder="Paste your complete job description here. Include details about the role, required skills, location, stipend, and any perks..."
                value={jobDescription}
                onChange={(e) => {
                  setJobDescription(e.target.value);
                  setHasAnalyzed(false);
                }}
                className="min-h-[200px] resize-none"
                disabled={isLoading || isAnalyzing}
                maxLength={5000}
              />
              <div className="flex justify-between items-center text-xs">
                <span className={jdCharCount < 100 ? 'text-muted-foreground' : 'text-primary'}>
                  {jdCharCount}/5000 characters {jdCharCount < 100 && '(min 100)'}
                </span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAnalyzeJD}
                  disabled={!isJDValid || isAnalyzing || isLoading}
                  className="gap-2"
                >
                  {isAnalyzing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      Analyze JD
                    </>
                  )}
                </Button>
              </div>
            </div>

            <AnimatePresence>
              {hasAnalyzed && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="bg-primary/5 border border-primary/20 rounded-lg p-3"
                >
                  <p className="text-sm text-primary flex items-center gap-2">
                    <Sparkles className="w-4 h-4" />
                    Analysis complete! Review the extracted details below and make any adjustments.
                  </p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Job Title */}
            <div className="space-y-2">
              <Label htmlFor="title" className="flex items-center">
                Job Title *
                <AISuggestedHint show={titleSuggested} />
              </Label>
              <div className="relative">
                <Briefcase className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="title"
                  type="text"
                  placeholder="e.g., Software Development Intern"
                  value={title}
                  onChange={(e) => {
                    setTitle(e.target.value);
                    setTitleSuggested(false);
                  }}
                  className="pl-10"
                  disabled={isLoading || isAnalyzing}
                  maxLength={100}
                />
              </div>
            </div>

            {/* Required Skills */}
            <div className="space-y-2">
              <Label className="flex items-center">
                Required Skills *
                <AISuggestedHint show={skillsSuggested} />
              </Label>
              <div className="flex gap-2">
                <Input
                  type="text"
                  placeholder="Add a skill and press Enter"
                  value={skillInput}
                  onChange={(e) => setSkillInput(e.target.value)}
                  onKeyDown={handleSkillKeyDown}
                  disabled={isLoading || isAnalyzing}
                  maxLength={50}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={handleAddSkill}
                  disabled={!skillInput.trim() || isLoading || isAnalyzing}
                >
                  <Plus className="w-4 h-4" />
                </Button>
              </div>
              {skills.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {skills.map((skill) => (
                    <Badge key={skill} variant="secondary" className="gap-1">
                      {skill}
                      <button
                        type="button"
                        onClick={() => handleRemoveSkill(skill)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Location */}
            <div className="space-y-2">
              <Label htmlFor="location" className="flex items-center">
                Location *
                <AISuggestedHint show={locationSuggested} />
              </Label>
              <div className="relative">
                <MapPin className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="location"
                  type="text"
                  placeholder="e.g., Bangalore, Karnataka or Remote"
                  value={locationLabel}
                  onChange={(e) => {
                    setLocationLabel(e.target.value);
                    setLocationSuggested(false);
                  }}
                  className="pl-10"
                  disabled={isLoading || isAnalyzing}
                  maxLength={100}
                />
              </div>
            </div>

            {/* Intake */}
            <div className="space-y-2">
              <Label htmlFor="intake" className="flex items-center">
                Number of Positions *
                <AISuggestedHint show={intakeSuggested} />
              </Label>
              <div className="relative">
                <Users className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="intake"
                  type="number"
                  placeholder="e.g., 5"
                  value={intake}
                  onChange={(e) => {
                    setIntake(e.target.value);
                    setIntakeSuggested(false);
                  }}
                  className="pl-10"
                  disabled={isLoading || isAnalyzing}
                  min={1}
                  max={100}
                />
              </div>
            </div>

            {/* Stipend (Optional) */}
            <div className="space-y-2">
              <Label htmlFor="stipend" className="flex items-center">
                Stipend (₹/month)
                <AISuggestedHint show={stipendSuggested} />
              </Label>
              <div className="relative">
                <IndianRupee className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="stipend"
                  type="number"
                  placeholder="e.g., 15000"
                  value={stipend}
                  onChange={(e) => {
                    setStipend(e.target.value);
                    setStipendSuggested(false);
                  }}
                  className="pl-10"
                  disabled={isLoading || isAnalyzing}
                  min={0}
                />
              </div>
            </div>

            {/* Perks (Optional) */}
            <div className="space-y-2">
              <Label htmlFor="perks" className="flex items-center">
                Perks & Benefits
                <AISuggestedHint show={perksSuggested} />
              </Label>
              <div className="relative">
                <Gift className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
                <Textarea
                  id="perks"
                  placeholder="e.g., Certificate, Letter of Recommendation, Flexible Hours..."
                  value={perks}
                  onChange={(e) => {
                    setPerks(e.target.value);
                    setPerksSuggested(false);
                  }}
                  className="pl-10 min-h-[80px] resize-none"
                  disabled={isLoading || isAnalyzing}
                  maxLength={500}
                />
              </div>
            </div>

            {/* Error Display */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="bg-destructive/10 border border-destructive/30 rounded-lg p-3"
                >
                  <p className="text-sm text-destructive">{error}</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Submit Button */}
            <Button
              type="submit"
              className="w-full"
              disabled={isLoading || isAnalyzing}
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Creating Job...
                </>
              ) : (
                'Create Job Posting'
              )}
            </Button>
          </form>
        </motion.div>

        {/* Aura Guidance */}
        <div className="mt-6">
          <AuraGuidance
            message="Tip: Include specific technical skills, preferred experience level, and whether the role is remote, hybrid, or on-site to attract better matches."
          />
        </div>
      </div>
    </div>
  );
};

export default CreateJob;
