// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Resume Version Card Component
 * 
 * OWNERSHIP: SYSTEM
 * 
 * Displays resume version information with clear indication
 * of which version was used for matching.
 */

import {
  FileText,
  Clock,
  CheckCircle2,
  Archive,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ResumeVersion, ResumeStatus } from '@/types/aura';

// ============================================================================
// TYPES
// ============================================================================

interface ResumeVersionCardProps {
  resume: ResumeVersion;
  isCurrentVersion?: boolean;
  matchVersionUsed?: number;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-IN', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ============================================================================
// STATUS BADGE
// ============================================================================

interface StatusBadgeProps {
  status: ResumeStatus;
}

function StatusBadge({ status }: StatusBadgeProps) {
  const configs: Record<ResumeStatus, { label: string; className: string; icon: React.ElementType }> = {
    active: {
      label: 'Active',
      className: 'bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/30',
      icon: CheckCircle2,
    },
    archived: {
      label: 'Archived',
      className: 'bg-muted text-muted-foreground',
      icon: Archive,
    },
    pending_extraction: {
      label: 'Processing',
      className: 'bg-primary/20 text-primary border-primary/30',
      icon: Loader2,
    },
  };

  const config = configs[status];
  const Icon = config.icon;

  return (
    <Badge className={config.className} variant="outline">
      <Icon className={`h-3 w-3 mr-1 ${status === 'pending_extraction' ? 'animate-spin' : ''}`} />
      {config.label}
    </Badge>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export function ResumeVersionCard({
  resume,
  isCurrentVersion = false,
  matchVersionUsed,
}: ResumeVersionCardProps) {
  const wasUsedForMatch = matchVersionUsed === resume.version;

  return (
    <Card className={isCurrentVersion ? 'border-primary/30' : ''}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base font-medium">
              Version {resume.version}
            </CardTitle>
            {isCurrentVersion && (
              <Badge variant="secondary" className="text-xs">Current</Badge>
            )}
          </div>
          <StatusBadge status={resume.status} />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* File Info */}
        <div className="text-sm">
          <p className="font-medium text-foreground truncate" title={resume.fileName}>
            {resume.fileName}
          </p>
          <p className="text-muted-foreground text-xs">
            {formatFileSize(resume.fileSize)} • Uploaded {formatDate(resume.uploadedAt)}
          </p>
        </div>

        {/* Skills */}
        {resume.extractedSkills.length > 0 && (
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">
              {resume.skillsConfirmed ? 'Confirmed Skills' : 'Extracted Skills (pending confirmation)'}
            </p>
            <div className="flex flex-wrap gap-1">
              {resume.extractedSkills.slice(0, 5).map((skill) => (
                <Badge key={skill} variant="secondary" className="text-xs">
                  {skill}
                </Badge>
              ))}
              {resume.extractedSkills.length > 5 && (
                <Badge variant="outline" className="text-xs">
                  +{resume.extractedSkills.length - 5} more
                </Badge>
              )}
            </div>
          </div>
        )}

        {/* Match Usage Notice */}
        {wasUsedForMatch && (
          <div className="flex items-center gap-2 text-xs text-primary bg-primary/10 rounded-lg p-2">
            <Clock className="h-3.5 w-3.5" />
            <span>This version was used for your current match</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// RESUME HISTORY LIST
// ============================================================================

interface ResumeHistoryListProps {
  currentVersion: ResumeVersion | null;
  archivedVersions: ResumeVersion[];
  matchVersionUsed?: number;
}

export function ResumeHistoryList({
  currentVersion,
  archivedVersions,
  matchVersionUsed,
}: ResumeHistoryListProps) {
  if (!currentVersion && archivedVersions.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-8 text-center">
          <FileText className="h-8 w-8 text-muted-foreground mb-2" />
          <p className="text-sm text-muted-foreground">
            No resume uploaded yet
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {currentVersion && (
        <ResumeVersionCard
          resume={currentVersion}
          isCurrentVersion
          matchVersionUsed={matchVersionUsed}
        />
      )}
      
      {archivedVersions.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-muted-foreground">
            Previous Versions ({archivedVersions.length})
          </h4>
          {archivedVersions.map((resume) => (
            <ResumeVersionCard
              key={`${resume.resumeId}-v${resume.version}`}
              resume={resume}
              matchVersionUsed={matchVersionUsed}
            />
          ))}
        </div>
      )}
    </div>
  );
}
