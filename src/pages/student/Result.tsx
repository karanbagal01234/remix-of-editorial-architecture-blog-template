// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Result Page
 * 
 * BACKEND AUTHORITY MODEL:
 * - All match data comes from backend
 * - Frontend only renders backend-provided state
 * - NO mock data or local state inference
 * 
 * OWNERSHIP: SYSTEM
 * STUDENT ACCESS: READ-ONLY
 */

import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Loader2, 
  UserCheck, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Users,
  Building2,
  MapPin,
  Gauge,
  Shield,
  Sparkles,
  Lock,
  AlertCircle
} from 'lucide-react';
import StudentHeader from '@/components/StudentHeader';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import api from '@/utils/api';

// ============================================================================
// TYPES - Backend-owned, read-only
// ============================================================================

type StudentMatchStatus = 
  | 'processing' 
  | 'under_review' 
  | 'accepted' 
  | 'rejected' 
  | 'waitlisted' 
  | 'position_filled';

interface MatchResultData {
  status: StudentMatchStatus;
  roleTitle: string;
  companyName: string;
  location: string;
  matchScore: number;
  explanations: string[];
}

// ============================================================================
// STATUS CONFIGURATIONS - Read-only system states
// ============================================================================
interface StatusConfig {
  readonly icon: React.ElementType;
  readonly title: string;
  readonly description: string;
  readonly bgClass: string;
  readonly iconClass: string;
  readonly badgeVariant: 'default' | 'secondary' | 'destructive' | 'outline';
  readonly nextSteps: string;
  readonly showMatchDetails: boolean;
}

const STATUS_CONFIGS: Record<StudentMatchStatus, StatusConfig> = {
  processing: {
    icon: Loader2,
    title: 'Processing',
    description: 'Your profile is currently being evaluated by the system.',
    bgClass: 'bg-muted/50 border-muted',
    iconClass: 'text-muted-foreground animate-spin',
    badgeVariant: 'secondary',
    nextSteps: 'No action required. The system is evaluating your profile against available positions.',
    showMatchDetails: false
  },
  under_review: {
    icon: UserCheck,
    title: 'Matched – Under Review',
    description: 'A company is reviewing your profile.',
    bgClass: 'bg-secondary/20 border-secondary/40',
    iconClass: 'text-secondary',
    badgeVariant: 'secondary',
    nextSteps: 'Please wait while the company reviews your profile. You will be notified of their decision.',
    showMatchDetails: true
  },
  accepted: {
    icon: CheckCircle2,
    title: 'Accepted',
    description: "Congratulations! You've been accepted for this role.",
    bgClass: 'bg-chart-4/20 border-chart-4/40',
    iconClass: 'text-chart-4',
    badgeVariant: 'default',
    nextSteps: 'The company will contact you with onboarding details. Check your registered email and phone.',
    showMatchDetails: true
  },
  rejected: {
    icon: XCircle,
    title: 'Not Selected',
    description: 'You were not selected for this role.',
    bgClass: 'bg-destructive/10 border-destructive/30',
    iconClass: 'text-destructive',
    badgeVariant: 'destructive',
    nextSteps: "You'll automatically be considered for future matches based on your profile.",
    showMatchDetails: true
  },
  waitlisted: {
    icon: Clock,
    title: 'Waitlisted',
    description: 'You are on hold. The company may review you again.',
    bgClass: 'bg-chart-5/20 border-chart-5/40',
    iconClass: 'text-chart-5',
    badgeVariant: 'outline',
    nextSteps: 'Your profile remains active. The company may reach out if positions become available.',
    showMatchDetails: true
  },
  position_filled: {
    icon: Users,
    title: 'Position Filled',
    description: "This position has been filled. You'll be considered for other roles.",
    bgClass: 'bg-muted/50 border-muted',
    iconClass: 'text-muted-foreground',
    badgeVariant: 'secondary',
    nextSteps: "You'll automatically be considered for future matches. No action required.",
    showMatchDetails: true
  }
};

// ============================================================================
// LOADING SKELETON
// ============================================================================
const ResultSkeleton: React.FC = () => (
  <div className="space-y-6">
    <Skeleton className="h-32 w-full rounded-xl" />
    <Skeleton className="h-48 w-full rounded-xl" />
    <Skeleton className="h-36 w-full rounded-xl" />
  </div>
);

// ============================================================================
// COMPONENT: Student Result Page (READ-ONLY, SYSTEM-OWNED)
// ============================================================================
const Result: React.FC = () => {
  const [matchData, setMatchData] = useState<MatchResultData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  /**
   * BACKEND-DRIVEN DATA FETCH
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   * All match data comes from backend. Frontend never infers state.
   */
  useEffect(() => {
    const fetchMatchResult = async () => {
      try {
        const response = await api.get<MatchResultData>('/student/match-result');
        setMatchData(response.data);
      } catch {
        setError('Unable to load match result. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchMatchResult();
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
        <div className="max-w-2xl mx-auto space-y-6">
          <StudentHeader />
          <ResultSkeleton />
        </div>
      </div>
    );
  }

  if (error || !matchData) {
    return (
      <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
        <div className="max-w-2xl mx-auto space-y-6">
          <StudentHeader />
          <Card className="border-destructive/30">
            <CardContent className="pt-6">
              <div className="flex flex-col items-center text-center space-y-4">
                <AlertCircle className="w-12 h-12 text-destructive" />
                <p className="text-muted-foreground">{error || 'No match data available'}</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const config = STATUS_CONFIGS[matchData.status];
  const Icon = config.icon;

  return (
    <div className="min-h-screen p-6 bg-gradient-to-br from-background via-muted/30 to-background">
      <div className="max-w-2xl mx-auto space-y-6">
        <StudentHeader />

        {/* Page Title */}
        <motion.div 
          className="text-center"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="text-2xl font-bold text-foreground mb-1">Your Match Status</h1>
          <p className="text-sm text-muted-foreground flex items-center justify-center gap-1.5">
            <Shield className="w-3.5 h-3.5" />
            This result was generated by the Aura matching system
          </p>
        </motion.div>

        {/* Section 1: Status Banner (Prominent) */}
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
        >
          <Card className={`${config.bgClass} border-2`}>
            <CardContent className="pt-6">
              <div className="flex flex-col items-center text-center space-y-4">
                <div className="w-16 h-16 rounded-full bg-background/80 flex items-center justify-center">
                  <Icon className={`w-8 h-8 ${config.iconClass}`} />
                </div>
                <div className="space-y-2">
                  <Badge variant={config.badgeVariant} className="text-xs font-medium">
                    {config.title}
                  </Badge>
                  <p className="text-base text-foreground font-medium max-w-md">
                    {config.description}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Section 2: Match Summary Card (Only if matched) */}
        {config.showMatchDetails && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <Card className="glass-strong">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg font-semibold">Match Summary</CardTitle>
                  <Badge variant="outline" className="text-xs gap-1">
                    <Lock className="w-3 h-3" />
                    System Generated
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Role & Company */}
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <Building2 className="w-5 h-5 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="font-medium text-foreground">{matchData.roleTitle}</p>
                      <p className="text-sm text-muted-foreground">{matchData.companyName}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <MapPin className="w-5 h-5 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">{matchData.location}</p>
                  </div>
                </div>

                <Separator />

                {/* Match Score - Read Only */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Gauge className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-medium text-foreground">System Score</span>
                    </div>
                    <span className="text-sm text-muted-foreground">{matchData.matchScore}%</span>
                  </div>
                  <div className="relative h-3 bg-muted rounded-full overflow-hidden">
                    <motion.div 
                      className="absolute inset-y-0 left-0 bg-gradient-to-r from-primary to-secondary rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${matchData.matchScore}%` }}
                      transition={{ duration: 0.8, delay: 0.4 }}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground text-center">
                    Read-only · Calculated by Aura
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Section 3: Why You Were Matched (Only if matched) */}
        {config.showMatchDetails && matchData.explanations.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <Card className="glass">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg font-semibold flex items-center gap-2">
                    <Sparkles className="w-5 h-5 text-primary" />
                    Why You Were Matched
                  </CardTitle>
                  <Badge variant="outline" className="text-xs">
                    Generated by Aura
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <ul className="space-y-3">
                  {matchData.explanations.map((reason, index) => (
                    <motion.li 
                      key={index}
                      className="flex items-start gap-3 text-sm text-muted-foreground"
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.5 + index * 0.1 }}
                    >
                      <span className="w-5 h-5 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-medium shrink-0 mt-0.5">
                        {index + 1}
                      </span>
                      <span>{reason}</span>
                    </motion.li>
                  ))}
                </ul>
                <p className="text-xs text-muted-foreground text-center mt-4 pt-3 border-t border-border/50">
                  Algorithm details are not shown for fairness
                </p>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Section 4: Next Steps */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="bg-primary/5 border-primary/20">
            <CardHeader className="pb-2">
              <CardTitle className="text-base font-semibold text-primary">Next Steps</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-foreground">{config.nextSteps}</p>
            </CardContent>
          </Card>
        </motion.div>

        {/* Section 5: System Notice */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="text-center py-4"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-muted/50 border border-border/50">
            <Shield className="w-4 h-4 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">
              Aura controls matching logic. Outcomes cannot be edited by students or companies.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default Result;
