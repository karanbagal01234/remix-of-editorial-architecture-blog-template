// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * JobMatches - Review system-generated candidate matches
 * 
 * ═══════════════════════════════════════════════════════════════
 * UI OWNERSHIP RULES (READ-ONLY)
 * ═══════════════════════════════════════════════════════════════
 * 
 * This component DISPLAYS system-generated data.
 * It NEVER computes, filters, sorts, or modifies match data.
 * 
 * COMPANY CAN:
 * - View match proposals (system order)
 * - See explanations ("why" not "how")
 * - Perform binary actions: Approve | Reject | Hold
 * 
 * COMPANY CANNOT:
 * - Edit scores
 * - Reorder candidates
 * - Filter candidates
 * - See unmatched students
 * - Undo after job closure
 * 
 * All data is labeled as "System Generated · Not Editable"
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useCompany } from '@/context/CompanyContext';
import CompanyHeader from '@/components/CompanyHeader';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Alert, AlertDescription } from '@/components/ui/alert';
import LoadingSkeleton from '@/components/LoadingSkeleton';
import { 
  MapPin, 
  Users, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Lock,
  ChevronDown,
  ChevronUp,
  Sparkles,
  ArrowLeft,
  AlertTriangle,
  GraduationCap,
  ShieldCheck
} from 'lucide-react';
import * as matchingApi from '@/api/matchingEngine.api';
import type { MatchProposal, JobMatchSummary } from '@/types/match';

const JobMatches: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const { jobs, refreshJobs } = useCompany();
  
  const [matches, setMatches] = useState<MatchProposal[]>([]);
  const [summary, setSummary] = useState<JobMatchSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [expandedMatch, setExpandedMatch] = useState<string | null>(null);
  
  const job = jobs.find(j => j.id === jobId);
  
  const loadMatches = useCallback(async () => {
    if (!jobId || !job) return;
    
    try {
      setIsLoading(true);
      const [matchData, summaryData] = await Promise.all([
        matchingApi.getMatchesForJob(jobId),
        matchingApi.getJobMatchSummary(jobId, job.intake)
      ]);
      setMatches(matchData);
      setSummary(summaryData);
    } catch (error) {
      console.error('[JobMatches] Failed to load matches:', error);
    } finally {
      setIsLoading(false);
    }
  }, [jobId, job]);
  
  useEffect(() => {
    loadMatches();
  }, [loadMatches]);
  
  const handleAction = async (matchId: string, action: 'approve' | 'reject' | 'hold') => {
    setActionLoading(matchId);
    try {
      await matchingApi.performMatchAction(matchId, action);
      await loadMatches();
      await refreshJobs(); // Sync job status if closed
    } catch (error) {
      console.error(`[JobMatches] Failed to ${action} match:`, error);
    } finally {
      setActionLoading(null);
    }
  };
  
  const getStatusBadge = (status: MatchProposal['status']) => {
    switch (status) {
      case 'approved':
        return <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">Approved</Badge>;
      case 'rejected':
        return <Badge variant="destructive">Rejected</Badge>;
      case 'hold':
        return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30">On Hold</Badge>;
      case 'locked':
        return <Badge variant="secondary"><Lock className="w-3 h-3 mr-1" />Locked</Badge>;
      default:
        return <Badge variant="outline">Pending Review</Badge>;
    }
  };
  
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-muted-foreground';
  };
  
  const getAlignmentBadge = (alignment: MatchProposal['preferenceAlignment']) => {
    switch (alignment) {
      case 'strong':
        return <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">Strong Fit</Badge>;
      case 'moderate':
        return <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20">Moderate Fit</Badge>;
      default:
        return <Badge variant="outline">Weak Fit</Badge>;
    }
  };
  
  if (!job) {
    return (
      <div className="min-h-screen bg-background">
        <CompanyHeader />
        <main className="container mx-auto px-4 py-8 max-w-4xl">
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>Job not found. Please return to job status.</AlertDescription>
          </Alert>
          <Button variant="outline" className="mt-4" onClick={() => navigate('/company/jobs/status')}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Jobs
          </Button>
        </main>
      </div>
    );
  }
  
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <CompanyHeader />
        <main className="container mx-auto px-4 py-8 max-w-4xl">
          <LoadingSkeleton type="card" />
        </main>
      </div>
    );
  }
  
  const isJobClosed = job.status === 'closed';
  const intakeFull = summary ? summary.intakeRemaining === 0 : false;
  
  return (
    <div className="min-h-screen bg-background">
      <CompanyHeader />
      
      <main className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Back Navigation */}
        <Button 
          variant="ghost" 
          className="mb-6" 
          onClick={() => navigate('/company/jobs/status')}
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Job Status
        </Button>
        
        {/* Job Summary Card */}
        <Card className="mb-6 border-primary/20">
          <CardHeader className="pb-3">
            <div className="flex items-start justify-between">
              <div>
                <CardTitle className="text-xl">{job.title}</CardTitle>
                <CardDescription className="flex items-center gap-4 mt-2">
                  <span className="flex items-center gap-1">
                    <MapPin className="w-4 h-4" />
                    {job.location.label}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="w-4 h-4" />
                    Intake: {job.intake}
                  </span>
                </CardDescription>
              </div>
              <Badge 
                className={
                  isJobClosed 
                    ? 'bg-muted text-muted-foreground' 
                    : 'bg-primary/20 text-primary border-primary/30'
                }
              >
                {isJobClosed ? 'Closed' : 'Matched'}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            {summary && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                <div className="text-center p-3 rounded-lg bg-muted/50">
                  <div className="text-2xl font-bold text-foreground">{summary.totalProposals}</div>
                  <div className="text-muted-foreground">Total Matches</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-emerald-500/10">
                  <div className="text-2xl font-bold text-emerald-400">{summary.approved}</div>
                  <div className="text-muted-foreground">Approved</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-destructive/10">
                  <div className="text-2xl font-bold text-destructive">{summary.rejected}</div>
                  <div className="text-muted-foreground">Rejected</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-amber-500/10">
                  <div className="text-2xl font-bold text-amber-400">{summary.hold}</div>
                  <div className="text-muted-foreground">On Hold</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-primary/10">
                  <div className="text-2xl font-bold text-primary">{summary.intakeRemaining}</div>
                  <div className="text-muted-foreground">Remaining</div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
        
        {/* System Notice */}
        {(isJobClosed || intakeFull) && (
          <Alert className="mb-6 border-amber-500/30 bg-amber-500/5">
            <Lock className="h-4 w-4 text-amber-500" />
            <AlertDescription className="text-amber-200">
              {isJobClosed 
                ? 'This job has been closed. All remaining candidates have been locked.'
                : 'Intake capacity has been reached. Remaining candidates are locked.'}
            </AlertDescription>
          </Alert>
        )}
        
        {/* Match List - SYSTEM ORDER, NO FILTERING/SORTING */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-primary" />
              System-Generated Matches
            </h2>
            <Badge variant="outline" className="text-xs flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" />
              Read-Only · Ranked by System
            </Badge>
          </div>
          
          {matches.length === 0 ? (
            <Card className="p-8 text-center">
              <p className="text-muted-foreground">No matches generated yet.</p>
            </Card>
          ) : (
            matches.map(match => (
              <Card 
                key={match.id} 
                className={`transition-all ${
                  match.status === 'rejected' ? 'opacity-60' : ''
                } ${
                  match.status === 'approved' ? 'border-emerald-500/30' : ''
                }`}
              >
                <CardContent className="pt-6">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                    {/* Candidate Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                          <span className="text-lg font-semibold text-primary">
                            {match.candidateName.charAt(0)}
                          </span>
                        </div>
                        <div>
                          <h3 className="font-semibold text-foreground">{match.candidateName}</h3>
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <GraduationCap className="w-3 h-3" />
                            {match.candidateCourse}
                          </p>
                        </div>
                      </div>
                      
                      {/* Quick Stats */}
                      <div className="flex flex-wrap gap-2 mt-3">
                        {getStatusBadge(match.status)}
                        {getAlignmentBadge(match.preferenceAlignment)}
                        <Badge variant="outline" className="flex items-center gap-1">
                          <MapPin className="w-3 h-3" />
                          {match.distanceKm === 0 ? 'Remote' : `${match.distanceKm} km`}
                        </Badge>
                      </div>
                      
                      {/* Skills */}
                      <div className="flex flex-wrap gap-1 mt-3">
                        {match.candidateSkills.slice(0, 5).map((skill, i) => (
                          <Badge key={i} variant="secondary" className="text-xs">
                            {skill}
                          </Badge>
                        ))}
                        {match.candidateSkills.length > 5 && (
                          <Badge variant="secondary" className="text-xs">
                            +{match.candidateSkills.length - 5} more
                          </Badge>
                        )}
                      </div>
                    </div>
                    
                    {/* Score Meter - READ ONLY */}
                    <div className="flex flex-col items-center min-w-[100px]">
                      <div className={`text-3xl font-bold ${getScoreColor(match.score)}`}>
                        {match.score}
                      </div>
                      <Progress 
                        value={match.score} 
                        className="w-20 h-2 mt-1 pointer-events-none"
                      />
                      <span className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5" />
                        System Score
                      </span>
                    </div>
                  </div>
                  
                  {/* Expandable Explanation */}
                  <Collapsible 
                    open={expandedMatch === match.id}
                    onOpenChange={(open) => setExpandedMatch(open ? match.id : null)}
                  >
                    <CollapsibleTrigger asChild>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        className="w-full mt-4 text-muted-foreground hover:text-foreground"
                      >
                        <Sparkles className="w-4 h-4 mr-2" />
                        Why this match?
                        {expandedMatch === match.id ? (
                          <ChevronUp className="w-4 h-4 ml-2" />
                        ) : (
                          <ChevronDown className="w-4 h-4 ml-2" />
                        )}
                      </Button>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <div className="mt-4 p-4 rounded-lg bg-primary/5 border border-primary/10">
                        {/* System Ownership Notice */}
                        <div className="flex items-center gap-2 mb-3 pb-2 border-b border-primary/10">
                          <ShieldCheck className="w-4 h-4 text-primary" />
                          <span className="text-xs text-muted-foreground font-medium">
                            System Generated · Not Editable
                          </span>
                        </div>
                        
                        <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-primary" />
                          Why This Candidate Was Matched
                        </h4>
                        <ul className="space-y-2">
                          {match.explanation.map((item, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm">
                              <span className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${
                                item.weight === 'high' ? 'bg-emerald-400' :
                                item.weight === 'medium' ? 'bg-amber-400' : 'bg-muted-foreground'
                              }`} />
                              <span>
                                <strong className="text-foreground">{item.factor}:</strong>{' '}
                                <span className="text-muted-foreground">{item.value}</span>
                              </span>
                            </li>
                          ))}
                        </ul>
                        
                        {/* Fairness Indicators - Read Only */}
                        <div className="mt-4 pt-3 border-t border-primary/10">
                          <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                            <Lock className="w-3 h-3" />
                            Fairness Indicators (System-Controlled)
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {match.fairnessIndicators.localCandidateBoost && (
                              <Badge variant="outline" className="text-xs cursor-default">
                                Local Boost Applied
                              </Badge>
                            )}
                            {match.fairnessIndicators.diversityConsideration && (
                              <Badge variant="outline" className="text-xs cursor-default">
                                Diversity Considered
                              </Badge>
                            )}
                            <Badge variant="outline" className="text-xs cursor-default">
                              Skill Gap Tolerance: {match.fairnessIndicators.skillGapTolerance}%
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </CollapsibleContent>
                  </Collapsible>
                  
                  {/* Action Buttons */}
                  {(match.status === 'pending' || match.status === 'hold') && !isJobClosed && (
                    <div className="flex gap-2 mt-4 pt-4 border-t border-border">
                      <Button
                        size="sm"
                        className="flex-1 bg-emerald-600 hover:bg-emerald-700"
                        onClick={() => handleAction(match.id, 'approve')}
                        disabled={actionLoading === match.id || intakeFull}
                      >
                        {actionLoading === match.id ? (
                          <span className="animate-pulse">Processing...</span>
                        ) : (
                          <>
                            <CheckCircle2 className="w-4 h-4 mr-2" />
                            Approve
                          </>
                        )}
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => handleAction(match.id, 'reject')}
                        disabled={actionLoading === match.id}
                      >
                        <XCircle className="w-4 h-4 mr-2" />
                        Reject
                      </Button>
                      {match.status === 'pending' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleAction(match.id, 'hold')}
                          disabled={actionLoading === match.id}
                        >
                          <Clock className="w-4 h-4 mr-2" />
                          Hold
                        </Button>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </div>
        
        {/* System Ownership Notice */}
        <div className="mt-6 p-4 rounded-lg bg-muted/50 border border-border">
          <div className="flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="text-sm font-medium text-foreground mb-1">
                System-Owned Matching
              </p>
              <p className="text-xs text-muted-foreground">
                These candidates were selected by the matching engine based on skill overlap, location proximity, and preference alignment. 
                You can approve, reject, or hold candidates for review. When intake capacity is reached, remaining candidates are automatically locked.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default JobMatches;
