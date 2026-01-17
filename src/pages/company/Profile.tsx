// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { User, Building2, CheckCircle2, Briefcase, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import AIAvatar from '@/components/AIAvatar';
import AuraGuidance from '@/components/AuraGuidance';
import CompanyHeader from '@/components/CompanyHeader';
import { useCompany } from '@/context/CompanyContext';

const CompanyProfile: React.FC = () => {
  const navigate = useNavigate();
  const { company, updateCompanyProfile, isAuthenticated, isVerified, isInitialized, isLoading } = useCompany();
  
  const [contactPerson, setContactPerson] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);

  // Redirect logic
  useEffect(() => {
    if (!isInitialized) return;
    
    if (!isAuthenticated) {
      navigate('/company/login', { replace: true });
      return;
    }
    
    if (!isVerified) {
      navigate('/company/verify-email', { replace: true });
    }
  }, [isInitialized, isAuthenticated, isVerified, navigate]);

  // Pre-fill form if company data exists
  useEffect(() => {
    if (company?.contactPerson) {
      setContactPerson(company.contactPerson);
    }
  }, [company]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!contactPerson.trim()) {
      setError('Please enter a contact person name');
      return;
    }

    try {
      await updateCompanyProfile({ contactPerson: contactPerson.trim() });
      setSaved(true);
    } catch (err) {
      setError('Failed to save profile. Please try again.');
    }
  };

  if (!isInitialized || !isAuthenticated || !isVerified) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <CompanyHeader title="Company Profile" />
      
      <div className="flex items-center justify-center p-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="w-full max-w-md"
        >
          <div className="bg-card border border-border rounded-2xl shadow-xl p-8">
            <div className="text-center mb-8">
              <div className="flex justify-center mb-4">
                <AIAvatar size="lg" />
              </div>
              <h1 className="text-2xl font-bold text-foreground mb-2">
                Complete Your Profile
              </h1>
              <p className="text-muted-foreground">
                Set up your company profile to start hiring
              </p>
            </div>

            {/* Company Info Summary */}
            <div className="bg-muted/50 rounded-lg p-4 mb-6 space-y-2">
              <div className="flex items-center gap-2 text-sm">
                <Building2 className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Company:</span>
                <span className="font-medium text-foreground">{company?.companyName}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle2 className="w-4 h-4 text-green-500" />
                <span className="text-muted-foreground">Email:</span>
                <span className="font-medium text-foreground">{company?.email}</span>
              </div>
            </div>

            {saved || company?.status === 'active' ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center space-y-6"
              >
                <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-8 h-8 text-green-500" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-foreground mb-2">
                    Profile Complete!
                  </h2>
                  <p className="text-muted-foreground">
                    Your company profile has been set up successfully.
                  </p>
                </div>
                <Button
                  onClick={() => navigate('/company/jobs/create')}
                  className="w-full"
                >
                  <Briefcase className="w-4 h-4 mr-2" />
                  Create Job Posting
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </motion.div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="contactPerson">Contact Person Name</Label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="contactPerson"
                      type="text"
                      placeholder="Enter your full name"
                      value={contactPerson}
                      onChange={(e) => setContactPerson(e.target.value)}
                      className="pl-10"
                      disabled={isLoading}
                    />
                  </div>
                </div>

                {error && (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-sm text-destructive text-center"
                  >
                    {error}
                  </motion.p>
                )}

                <Button
                  type="submit"
                  className="w-full"
                  disabled={isLoading || !contactPerson.trim()}
                >
                  {isLoading ? 'Saving...' : 'Complete Profile'}
                </Button>
              </form>
            )}
          </div>

          <div className="mt-6">
            <AuraGuidance
              message="Once your profile is complete, you'll be able to create job postings and access our AI-powered candidate matching system."
            />
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default CompanyProfile;
