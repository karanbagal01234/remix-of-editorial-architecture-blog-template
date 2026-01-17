// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Withdraw Application Dialog Component
 * 
 * OWNERSHIP: STUDENT (limited)
 * 
 * Allows students to withdraw from the current matching cycle.
 * Triggers cooldown period before they can re-apply.
 */

import { useState, useEffect } from 'react';
import {
  LogOut,
  AlertTriangle,
  Clock,
  Shield,
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
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import type { ApplicationState } from '@/types/aura';
import { SYSTEM_CONFIG } from '@/types/aura';
import * as applicationApi from '@/api/application.api';

// ============================================================================
// TYPES
// ============================================================================

interface WithdrawDialogProps {
  onWithdraw?: (state: ApplicationState) => void;
}

// ============================================================================
// COOLDOWN DISPLAY
// ============================================================================

interface CooldownDisplayProps {
  state: ApplicationState;
}

function CooldownDisplay({ state }: CooldownDisplayProps) {
  const [remaining, setRemaining] = useState(applicationApi.getCooldownRemaining(state));

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(applicationApi.getCooldownRemaining(state));
    }, 60000); // Update every minute

    return () => clearInterval(interval);
  }, [state]);

  if (remaining.canReapply) {
    return null;
  }

  return (
    <div className="space-y-3 p-4 bg-muted/50 rounded-lg border">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Cooldown Period</span>
        <Badge variant="secondary" className="gap-1">
          <Clock className="h-3 w-3" />
          Active
        </Badge>
      </div>
      
      <div className="flex items-center gap-3">
        <div className="text-center px-4 py-2 bg-background rounded-lg border">
          <div className="text-2xl font-bold text-foreground">{remaining.days}</div>
          <div className="text-xs text-muted-foreground">Days</div>
        </div>
        <div className="text-center px-4 py-2 bg-background rounded-lg border">
          <div className="text-2xl font-bold text-foreground">{remaining.hours}</div>
          <div className="text-xs text-muted-foreground">Hours</div>
        </div>
        <div className="text-sm text-muted-foreground">remaining</div>
      </div>

      <p className="text-sm text-muted-foreground">
        You withdrew on {new Date(state.withdrawnAt!).toLocaleDateString('en-IN', {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        })}. You can re-apply after the cooldown period ends.
      </p>

      {state.withdrawalReason && (
        <div className="text-sm text-muted-foreground">
          <strong>Reason:</strong> {state.withdrawalReason}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export function WithdrawDialog({ onWithdraw }: WithdrawDialogProps) {
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reason, setReason] = useState('');
  const [canWithdraw, setCanWithdraw] = useState(true);
  const [withdrawReason, setWithdrawReason] = useState<string | null>(null);
  const [applicationState, setApplicationState] = useState<ApplicationState | null>(null);

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const [state, withdrawCheck] = await Promise.all([
          applicationApi.getApplicationState(),
          applicationApi.canWithdrawApplication(),
        ]);
        setApplicationState(state);
        setCanWithdraw(withdrawCheck.canWithdraw);
        setWithdrawReason(withdrawCheck.reason);
      } catch (error) {
        console.error('Error checking withdrawal status:', error);
      } finally {
        setIsLoading(false);
      }
    };
    
    if (isOpen) {
      checkStatus();
    }
  }, [isOpen]);

  const handleWithdraw = async () => {
    if (!reason.trim()) {
      toast({
        title: 'Please provide a reason',
        variant: 'destructive',
      });
      return;
    }

    setIsSubmitting(true);
    try {
      const newState = await applicationApi.withdrawApplication(reason);
      setApplicationState(newState);
      setCanWithdraw(false);
      onWithdraw?.(newState);
      toast({
        title: 'Application Withdrawn',
        description: `You have been removed from the current matching cycle. Cooldown: ${SYSTEM_CONFIG.COOLDOWN_DAYS} days.`,
      });
    } catch (error) {
      toast({
        title: 'Error withdrawing application',
        description: error instanceof Error ? error.message : 'Please try again',
        variant: 'destructive',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const isInCooldown = applicationState?.status === 'cooldown';

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="gap-2 text-destructive border-destructive/50 hover:bg-destructive/10"
        >
          <LogOut className="h-4 w-4" />
          Withdraw Application
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <LogOut className="h-5 w-5 text-destructive" />
            {isInCooldown ? 'Withdrawal Status' : 'Withdraw Application'}
          </DialogTitle>
          <DialogDescription>
            {isInCooldown
              ? 'Your application has been withdrawn.'
              : 'Remove yourself from the current matching cycle.'}
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-8 text-center text-muted-foreground">
            Loading...
          </div>
        ) : isInCooldown && applicationState ? (
          <CooldownDisplay state={applicationState} />
        ) : !canWithdraw ? (
          <div className="space-y-4 py-2">
            <div className="flex items-start gap-2 p-3 bg-muted rounded-lg">
              <Shield className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-0.5" />
              <p className="text-sm text-muted-foreground">
                {withdrawReason || 'You cannot withdraw at this time.'}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-2">
            {/* Warning */}
            <div className="flex items-start gap-2 p-3 bg-destructive/10 border border-destructive/30 rounded-lg">
              <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
              <div className="text-sm text-destructive">
                <p className="font-medium mb-1">Warning: This action is significant</p>
                <ul className="list-disc list-inside space-y-1 text-destructive/80">
                  <li>Withdrawing removes you from the current matching cycle</li>
                  <li>All pending offers will be cancelled</li>
                  <li>You must wait {SYSTEM_CONFIG.COOLDOWN_DAYS} days before re-applying</li>
                </ul>
              </div>
            </div>

            {/* Reason */}
            <div className="space-y-2">
              <Label>Reason for withdrawal *</Label>
              <Textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Please explain why you're withdrawing..."
                rows={3}
              />
              <p className="text-xs text-muted-foreground">
                This will be recorded for system improvement purposes.
              </p>
            </div>
          </div>
        )}

        <DialogFooter>
          {isInCooldown ? (
            <Button variant="outline" onClick={() => setIsOpen(false)}>
              Close
            </Button>
          ) : canWithdraw ? (
            <>
              <Button variant="outline" onClick={() => setIsOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleWithdraw}
                disabled={isSubmitting || !reason.trim()}
              >
                {isSubmitting ? 'Processing...' : 'Confirm Withdrawal'}
              </Button>
            </>
          ) : (
            <Button variant="outline" onClick={() => setIsOpen(false)}>
              Close
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
