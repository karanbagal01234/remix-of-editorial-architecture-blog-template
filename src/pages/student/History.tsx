// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Match History Page
 * 
 * BACKEND AUTHORITY MODEL:
 * - All history data comes from backend
 * - Frontend only renders backend-provided state
 * - NO mock data or local inference
 * 
 * OWNERSHIP: SYSTEM
 * STUDENT ACCESS: READ-ONLY
 */

import { useState, useEffect } from "react";
import StudentHeader from "@/components/StudentHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  History as HistoryIcon,
  MapPin,
  Calendar,
  ChevronDown,
  ChevronUp,
  Loader2,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  Users,
  AlertCircle,
  Sparkles,
  Info,
} from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import api from "@/utils/api";

// ============================================================================
// TYPES
// ============================================================================

type MatchHistoryStatus =
  | "processing"
  | "under_review"
  | "accepted"
  | "rejected"
  | "waitlisted"
  | "position_filled";

interface MatchHistoryItem {
  id: string;
  roleTitle: string;
  companyName: string;
  location: string;
  score: number;
  status: MatchHistoryStatus;
  generatedAt: string;
  explanation: string[];
  systemNote?: string;
}

// ============================================================================
// STATUS CONFIGURATION
// ============================================================================

interface StatusConfig {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
  className: string;
}

const STATUS_CONFIGS: Record<MatchHistoryStatus, StatusConfig> = {
  processing: {
    icon: Loader2,
    label: "Processing",
    variant: "secondary",
    className: "bg-muted text-muted-foreground",
  },
  under_review: {
    icon: Search,
    label: "Under Review",
    variant: "outline",
    className: "border-primary/50 text-primary bg-primary/10",
  },
  accepted: {
    icon: CheckCircle2,
    label: "Accepted",
    variant: "default",
    className: "bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/30",
  },
  rejected: {
    icon: XCircle,
    label: "Rejected",
    variant: "destructive",
    className: "bg-destructive/20 text-destructive border-destructive/30",
  },
  waitlisted: {
    icon: Clock,
    label: "Waitlisted",
    variant: "outline",
    className: "bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30",
  },
  position_filled: {
    icon: Users,
    label: "Position Filled",
    variant: "secondary",
    className: "bg-muted text-muted-foreground",
  },
};

// ============================================================================
// UTILITY FUNCTIONS (DISPLAY ONLY)
// ============================================================================

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

function formatTime(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ============================================================================
// TIMELINE ITEM COMPONENT
// ============================================================================

interface TimelineItemProps {
  item: MatchHistoryItem;
  isLast: boolean;
}

function TimelineItem({ item, isLast }: TimelineItemProps) {
  const [isOpen, setIsOpen] = useState(false);
  const statusConfig = STATUS_CONFIGS[item.status];
  const StatusIcon = statusConfig.icon;
  const hasDetails = item.explanation.length > 0 || item.systemNote;

  return (
    <div className="relative flex gap-4">
      {/* Timeline line */}
      {!isLast && (
        <div className="absolute left-[19px] top-12 bottom-0 w-0.5 bg-border" />
      )}

      {/* Timeline dot */}
      <div className="relative z-10 flex-shrink-0">
        <div
          className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
            item.status === "accepted"
              ? "bg-green-500/20 border-green-500"
              : item.status === "rejected"
              ? "bg-destructive/20 border-destructive"
              : "bg-muted border-border"
          }`}
        >
          <StatusIcon
            className={`h-5 w-5 ${
              item.status === "accepted"
                ? "text-green-600 dark:text-green-400"
                : item.status === "rejected"
                ? "text-destructive"
                : item.status === "processing"
                ? "animate-spin text-muted-foreground"
                : "text-muted-foreground"
            }`}
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 pb-8">
        <Card className="overflow-hidden">
          <CardContent className="p-4">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-3">
              <div>
                <h3 className="font-semibold text-foreground">
                  {item.roleTitle}
                </h3>
                <p className="text-sm text-muted-foreground">
                  {item.companyName}
                </p>
              </div>
              <Badge className={statusConfig.className} variant="outline">
                {statusConfig.label}
              </Badge>
            </div>

            {/* Details row */}
            <div className="flex flex-wrap gap-4 text-sm text-muted-foreground mb-3">
              <div className="flex items-center gap-1">
                <MapPin className="h-3.5 w-3.5" />
                <span>{item.location}</span>
              </div>
              <div className="flex items-center gap-1">
                <Calendar className="h-3.5 w-3.5" />
                <span>{formatDate(item.generatedAt)}</span>
                <span className="text-muted-foreground/60">
                  at {formatTime(item.generatedAt)}
                </span>
              </div>
            </div>

            {/* Score */}
            {item.score > 0 && (
              <div className="flex items-center gap-2 mb-3">
                <span className="text-xs text-muted-foreground">
                  System Score:
                </span>
                <div className="flex items-center gap-1.5">
                  <div className="h-2 w-24 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        item.score >= 75
                          ? "bg-green-500"
                          : item.score >= 50
                          ? "bg-amber-500"
                          : "bg-destructive"
                      }`}
                      style={{ width: `${item.score}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium">{item.score}%</span>
                </div>
                <Badge variant="secondary" className="text-xs">
                  <Sparkles className="h-3 w-3 mr-1" />
                  System Generated
                </Badge>
              </div>
            )}

            {/* Expandable details */}
            {hasDetails && (
              <Collapsible open={isOpen} onOpenChange={setIsOpen}>
                <CollapsibleTrigger className="flex items-center gap-1 text-sm text-primary hover:underline">
                  {isOpen ? (
                    <>
                      <ChevronUp className="h-4 w-4" />
                      Hide details
                    </>
                  ) : (
                    <>
                      <ChevronDown className="h-4 w-4" />
                      View details
                    </>
                  )}
                </CollapsibleTrigger>
                <CollapsibleContent className="pt-3 space-y-3">
                  {/* Why matched */}
                  {item.explanation.length > 0 && (
                    <div className="bg-muted/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-2">
                        <AlertCircle className="h-4 w-4 text-primary" />
                        <span className="text-sm font-medium">
                          Why you were matched
                        </span>
                        <Badge variant="outline" className="text-xs">
                          Generated by Aura
                        </Badge>
                      </div>
                      <ul className="space-y-1">
                        {item.explanation.map((point, idx) => (
                          <li
                            key={idx}
                            className="text-sm text-muted-foreground flex items-start gap-2"
                          >
                            <span className="text-primary mt-1.5">•</span>
                            <span>{point}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* System note */}
                  {item.systemNote && (
                    <div className="flex items-start gap-2 text-sm text-muted-foreground bg-muted/30 rounded-lg p-3">
                      <Info className="h-4 w-4 mt-0.5 flex-shrink-0" />
                      <div>
                        <span className="font-medium">System Note:</span>{" "}
                        {item.systemNote}
                      </div>
                    </div>
                  )}
                </CollapsibleContent>
              </Collapsible>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ============================================================================
// EMPTY STATE COMPONENT
// ============================================================================

function EmptyState() {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center justify-center py-16 text-center">
        <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mb-4">
          <HistoryIcon className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="font-semibold text-lg mb-2">
          You haven&apos;t been matched yet
        </h3>
        <p className="text-muted-foreground max-w-sm">
          Aura will record all matches here. Complete your profile to start
          receiving matches.
        </p>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// LOADING SKELETON
// ============================================================================

function LoadingSkeleton() {
  return (
    <div className="space-y-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="flex gap-4">
          <Skeleton className="w-10 h-10 rounded-full flex-shrink-0" />
          <div className="flex-1">
            <Skeleton className="h-32 w-full rounded-xl" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function History() {
  const [history, setHistory] = useState<MatchHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  /**
   * BACKEND-DRIVEN DATA FETCH
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   */
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await api.get<MatchHistoryItem[]>('/student/match-history');
        setHistory(response.data);
      } catch {
        setError('Unable to load match history. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <StudentHeader />
        <main className="container max-w-3xl mx-auto px-4 py-8">
          <div className="mb-8">
            <Skeleton className="h-8 w-48 mb-2" />
            <Skeleton className="h-4 w-64" />
          </div>
          <LoadingSkeleton />
        </main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background">
        <StudentHeader />
        <main className="container max-w-3xl mx-auto px-4 py-8">
          <Card className="border-destructive/30">
            <CardContent className="pt-6">
              <div className="flex flex-col items-center text-center space-y-4">
                <AlertCircle className="w-12 h-12 text-destructive" />
                <p className="text-muted-foreground">{error}</p>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  const hasHistory = history.length > 0;

  return (
    <div className="min-h-screen bg-background">
      <StudentHeader />

      <main className="container max-w-3xl mx-auto px-4 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
              <HistoryIcon className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">
                Match History
              </h1>
              <p className="text-muted-foreground">
                Your past and current matches generated by Aura
              </p>
            </div>
          </div>
        </div>

        {/* Timeline */}
        {hasHistory ? (
          <div className="space-y-0">
            {history.map((item, index) => (
              <TimelineItem
                key={item.id}
                item={item}
                isLast={index === history.length - 1}
              />
            ))}
          </div>
        ) : (
          <EmptyState />
        )}

        {/* Footer Notice */}
        <div className="mt-8 pt-6 border-t border-border">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Info className="h-4 w-4 flex-shrink-0" />
            <p>
              This history is system generated and cannot be edited.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
