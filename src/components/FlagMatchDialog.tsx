// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Flag Match Dialog Component
 * 
 * OWNERSHIP: STUDENT (limited)
 * 
 * Allows students to flag a match for review (explainability challenge).
 * Once submitted, the review request is read-only.
 */

import { useState } from 'react';
import {
  Flag,
  AlertTriangle,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import type { FlagReason, ReviewRequest } from '@/types/aura';
import { FLAG_REASON_LABELS } from '@/types/aura';
import * as reviewApi from '@/api/review.api';

// ============================================================================
// TYPES
// ============================================================================

interface FlagMatchDialogProps {
  matchId: string;
  existingReview?: ReviewRequest | null;
  onFlagSubmitted?: (review: ReviewRequest) => void;
  variant?: 'button' | 'link';
  disabled?: boolean;
}

// ============================================================================
// REVIEW STATUS DISPLAY
// ============================================================================

interface ReviewStatusProps {
  review: ReviewRequest;
}

function ReviewStatusDisplay({ review }: ReviewStatusProps) {
  const statusColors = {
    submitted: 'bg-primary/20 text-primary border-primary/30',
    under_review: 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30',
    resolved: 'bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/30',
  };

  const statusLabels = {
    submitted: 'Submitted',
    under_review: 'Under Review',
    resolved: 'Resolved',
  };

  return (
    <div className="space-y-3 p-4 bg-muted/50 rounded-lg border">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Review Request</span>
        <Badge className={statusColors[review.status]} variant="outline">
          {statusLabels[review.status]}
        </Badge>
      </div>
      
      <div className="text-sm text-muted-foreground">
        <p><strong>Reason:</strong> {FLAG_REASON_LABELS[review.reason]}</p>
        {review.otherReason && (
          <p className="mt-1"><strong>Details:</strong> {review.otherReason}</p>
        )}
        <p className="mt-1">
          <strong>Submitted:</strong>{' '}
          {new Date(review.createdAt).toLocaleDateString('en-IN', {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
          })}
        </p>
      </div>

      {review.status === 'resolved' && review.resolution && (
        <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 className="h-4 w-4 text-green-600" />
            <span className="text-sm font-medium text-green-700 dark:text-green-400">Resolution</span>
          </div>
          <p className="text-sm text-muted-foreground">{review.resolution}</p>
        </div>
      )}

      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Lock className="h-3 w-3" />
        <span>Review requests cannot be edited after submission</span>
      </div>
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export function FlagMatchDialog({
  matchId,
  existingReview,
  onFlagSubmitted,
  variant = 'button',
  disabled = false,
}: FlagMatchDialogProps) {
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reason, setReason] = useState<FlagReason | ''>('');
  const [otherReason, setOtherReason] = useState('');
  const [localReview, setLocalReview] = useState<ReviewRequest | null>(existingReview ?? null);

  const hasExistingReview = localReview !== null;

  const handleSubmit = async () => {
    if (!reason) {
      toast({
        title: 'Please select a reason',
        variant: 'destructive',
      });
      return;
    }

    if (reason === 'other' && !otherReason.trim()) {
      toast({
        title: 'Please provide details',
        description: 'The "Other" reason requires additional explanation',
        variant: 'destructive',
      });
      return;
    }

    setIsSubmitting(true);
    try {
      const review = await reviewApi.submitFlagRequest(
        matchId,
        reason,
        reason === 'other' ? otherReason : null
      );
      setLocalReview(review);
      onFlagSubmitted?.(review);
      toast({
        title: 'Review Request Submitted',
        description: 'Your flag has been recorded and will be reviewed.',
      });
    } catch (error) {
      toast({
        title: 'Error submitting flag',
        description: error instanceof Error ? error.message : 'Please try again',
        variant: 'destructive',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const trigger = variant === 'button' ? (
    <Button
      variant="outline"
      size="sm"
      disabled={disabled}
      className="gap-2"
    >
      <Flag className="h-4 w-4" />
      {hasExistingReview ? 'View Review' : 'Flag This Match'}
    </Button>
  ) : (
    <button
      disabled={disabled}
      className="flex items-center gap-1 text-sm text-primary hover:underline disabled:opacity-50"
    >
      <Flag className="h-3.5 w-3.5" />
      {hasExistingReview ? 'View Review' : 'Flag Match'}
    </button>
  );

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {trigger}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Flag className="h-5 w-5 text-primary" />
            {hasExistingReview ? 'Review Request Status' : 'Flag This Match'}
          </DialogTitle>
          <DialogDescription>
            {hasExistingReview
              ? 'Your review request has been submitted.'
              : 'Report an issue with how this match was generated.'}
          </DialogDescription>
        </DialogHeader>

        {hasExistingReview ? (
          <ReviewStatusDisplay review={localReview} />
        ) : (
          <div className="space-y-4 py-2">
            {/* Warning */}
            <div className="flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
              <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-amber-700 dark:text-amber-400">
                Review requests are final. You cannot edit or withdraw after submission.
              </p>
            </div>

            {/* Reason Select */}
            <div className="space-y-2">
              <Label>Reason for flagging *</Label>
              <Select value={reason} onValueChange={(val) => setReason(val as FlagReason)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a reason" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(FLAG_REASON_LABELS).map(([key, label]) => (
                    <SelectItem key={key} value={key}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Other Reason Text */}
            {reason === 'other' && (
              <div className="space-y-2">
                <Label>Please describe the issue *</Label>
                <Textarea
                  value={otherReason}
                  onChange={(e) => setOtherReason(e.target.value)}
                  placeholder="Describe why you believe this match was incorrect..."
                  rows={3}
                />
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          {hasExistingReview ? (
            <Button variant="outline" onClick={() => setIsOpen(false)}>
              Close
            </Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => setIsOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={isSubmitting || !reason}>
                {isSubmitting ? 'Submitting...' : 'Submit Flag'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
