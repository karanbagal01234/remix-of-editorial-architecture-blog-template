// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Briefcase, MapPin, Users, Clock, Plus, Loader2, Eye, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import CompanyHeader from '@/components/CompanyHeader';
import AuraGuidance from '@/components/AuraGuidance';
import { useCompany } from '@/context/CompanyContext';
import * as matchingApi from '@/api/matchingEngine.api';

const JobStatus: React.FC = () => {
  const navigate = useNavigate();
  const { jobs, refreshJobs } = useCompany();
  const [runningMatching, setRunningMatching] = useState<string | null>(null);

  // Auto-run matching for processing jobs
  useEffect(() => {
    const runMatchingForProcessingJobs = async () => {
      const processingJobs = jobs.filter(j => j.status === 'processing');
      for (const job of processingJobs) {
        try {
          setRunningMatching(job.id);
          await matchingApi.runMatching(job.id);
          await refreshJobs();
        } catch (error) {
          console.error('[JobStatus] Matching failed for job:', job.id, error);
        }
      }
      setRunningMatching(null);
    };
    
    if (jobs.some(j => j.status === 'processing')) {
      runMatchingForProcessingJobs();
    }
  }, [jobs.length]); // Only trigger when job count changes

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-IN', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <CompanyHeader title="Job Status" />

      <div className="max-w-3xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          {/* Header Section */}
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-foreground mb-2">
                Your Job Postings
              </h1>
              <p className="text-muted-foreground">
                {jobs.length} job{jobs.length !== 1 ? 's' : ''} submitted
              </p>
            </div>
            <Button onClick={() => navigate('/company/jobs/create')}>
              <Plus className="w-4 h-4 mr-2" />
              Create New Job
            </Button>
          </div>

          {/* Info Banner */}
          <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <Loader2 className="w-5 h-5 text-primary animate-spin mt-0.5" />
              <div>
                <p className="text-sm font-medium text-foreground mb-1">
                  Processing Your Requirements
                </p>
                <p className="text-sm text-muted-foreground">
                  Our system is analyzing your requirements. You'll receive candidates once matching completes.
                </p>
              </div>
            </div>
          </div>

          {/* Immutability Notice */}
          <div className="bg-muted/50 border border-border rounded-lg px-4 py-3 mb-6">
            <p className="text-xs text-muted-foreground">
              Once a job enters processing, it cannot be edited. Create a new job if requirements change.
            </p>
          </div>

          {/* Jobs List */}
          <div className="space-y-4">
            {jobs.map((job, index) => (
              <motion.div
                key={job.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
              >
                <Card>
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                          <Briefcase className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                          <CardTitle className="text-lg">{job.title}</CardTitle>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
                            <MapPin className="w-3 h-3" />
                            {job.location.label}
                          </div>
                        </div>
                      </div>
                      <Badge
                        variant={
                          job.status === 'matched' ? 'default' : 
                          job.status === 'closed' ? 'secondary' : 'outline'
                        }
                        className={`capitalize ${
                          job.status === 'matched' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : ''
                        }`}
                      >
                        {(job.status === 'processing' || runningMatching === job.id) && (
                          <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        )}
                        {job.status === 'matched' && <CheckCircle2 className="w-3 h-3 mr-1" />}
                        {job.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="flex items-center gap-2 text-sm">
                        <Users className="w-4 h-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Intake:</span>
                        <span className="font-medium text-foreground">{job.intake}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Created:</span>
                        <span className="font-medium text-foreground">{formatDate(job.createdAt)}</span>
                      </div>
                    </div>

                    <div>
                      <p className="text-sm text-muted-foreground mb-2">
                        Required Skills ({job.requiredSkills.length})
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {job.requiredSkills.map((skill) => (
                          <Badge key={skill} variant="outline">
                            {skill}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {job.stipend && (
                      <div className="mt-3 text-sm">
                        <span className="text-muted-foreground">Stipend: </span>
                        <span className="font-medium text-foreground">₹{job.stipend.toLocaleString('en-IN')}/month</span>
                      </div>
                    )}

                    {job.perks && (
                      <div className="mt-2 text-sm">
                        <span className="text-muted-foreground">Perks: </span>
                        <span className="text-foreground">{job.perks}</span>
                      </div>
                    )}

                    {/* View Matches Button */}
                    {(job.status === 'matched' || job.status === 'closed') && (
                      <Button
                        className="w-full mt-4"
                        onClick={() => navigate(`/company/jobs/matches/${job.id}`)}
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        View Matched Candidates
                      </Button>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>

        <div className="mt-6">
          <AuraGuidance
            message="Your job postings are being processed. Our AI is analyzing skill requirements to find the best matches from our candidate pool."
          />
        </div>
      </div>
    </div>
  );
};

export default JobStatus;
