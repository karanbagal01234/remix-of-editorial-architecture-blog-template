// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Offers Page
 * 
 * OWNERSHIP: SYSTEM
 * STUDENT ACCESS: CONTROLLED (Accept/Decline only)
 * 
 * Displays system-proposed offers with grace period countdowns.
 * Student can accept ONE offer (auto-expires others) or decline.
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Clock,
  CheckCircle2,
  XCircle,
  Building2,
  MapPin,
  AlertTriangle,
  Shield,
  Lock,
  FileText,
  Sparkles,
  Timer,
  Info,
} from 'lucide-react';
import StudentHeader from '@/components/StudentHeader';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { useToast } from '@/hooks/use-toast';
import type { Offer, OfferStatus } from '@/types/aura';
import * as offerApi from '@/api/offer.api';

// ============================================================================
// STATUS CONFIGURATION
// ============================================================================

interface StatusConfig {
  label: string;
  variant: 'default' | 'secondary' | 'destructive' | 'outline';
  className: string;
}

const STATUS_CONFIGS: Record<OfferStatus, StatusConfig> = {
  pending: {
    label: 'Awaiting Decision',
    variant: 'outline',
    className: 'border-primary/50 text-primary bg-primary/10',
  },
  accepted: {
    label: 'Accepted',
    variant: 'default',
    className: 'bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/30',
  },
  declined: {
    label: 'Declined',
    variant: 'secondary',
    className: 'bg-muted text-muted-foreground',
  },
  expired: {
    label: 'Expired',
    variant: 'destructive',
    className: 'bg-destructive/20 text-destructive border-destructive/30',
  },
  withdrawn: {
    label: 'Withdrawn',
    variant: 'secondary',
    className: 'bg-muted text-muted-foreground',
  },
  superseded: {
    label: 'Auto-Expired',
    variant: 'secondary',
    className: 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30',
  },
};

// ============================================================================
// GRACE PERIOD COUNTDOWN COMPONENT
// ============================================================================

interface GracePeriodCountdownProps {
  offer: Offer;
}

function GracePeriodCountdown({ offer }: GracePeriodCountdownProps) {
  const [remaining, setRemaining] = useState(offerApi.getGracePeriodRemaining(offer));

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(offerApi.getGracePeriodRemaining(offer));
    }, 60000); // Update every minute

    return () => clearInterval(interval);
  }, [offer]);

  if (offer.status !== 'pending') return null;

  if (remaining.expired) {
    return (
      <div className="flex items-center gap-2 text-destructive">
        <Timer className="h-4 w-4" />
        <span className="text-sm font-medium">Grace period expired</span>
      </div>
    );
  }

  return (
    <div className={`flex items-center gap-2 ${remaining.urgent ? 'text-destructive' : 'text-amber-600 dark:text-amber-400'}`}>
      <Timer className="h-4 w-4" />
      <span className="text-sm font-medium">
        {remaining.hours}h {remaining.minutes}m remaining
      </span>
      {remaining.urgent && (
        <Badge variant="destructive" className="text-xs">Urgent</Badge>
      )}
    </div>
  );
}

// ============================================================================
// OFFER CARD COMPONENT
// ============================================================================

interface OfferCardProps {
  offer: Offer;
  onAccept: (offerId: string) => Promise<void>;
  onDecline: (offerId: string) => Promise<void>;
  isProcessing: boolean;
  hasAcceptedOffer: boolean;
}

function OfferCard({ offer, onAccept, onDecline, isProcessing, hasAcceptedOffer }: OfferCardProps) {
  const statusConfig = STATUS_CONFIGS[offer.status];
  const isPending = offer.status === 'pending';
  const remaining = offerApi.getGracePeriodRemaining(offer);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <Card className={isPending ? 'border-primary/30' : ''}>
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <CardTitle className="text-lg font-semibold">{offer.roleTitle}</CardTitle>
              <div className="flex items-center gap-2 text-muted-foreground mt-1">
                <Building2 className="h-4 w-4" />
                <span className="text-sm">{offer.companyName}</span>
              </div>
            </div>
            <Badge className={statusConfig.className} variant="outline">
              {statusConfig.label}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Location */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <MapPin className="h-4 w-4" />
            <span>{offer.location}</span>
          </div>

          {/* Resume Version Notice */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/50 rounded-lg p-2">
            <FileText className="h-3.5 w-3.5" />
            <span>This match was generated using Resume v{offer.resumeVersionUsed}</span>
          </div>

          {/* Match Score */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">System Score</span>
              </div>
              <span className="text-sm font-medium">{offer.matchScore}%</span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-primary to-secondary rounded-full"
                style={{ width: `${offer.matchScore}%` }}
              />
            </div>
          </div>

          <Separator />

          {/* Why Matched */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Why you were matched</span>
              <Badge variant="outline" className="text-xs">
                <Lock className="h-3 w-3 mr-1" />
                System Generated
              </Badge>
            </div>
            <ul className="space-y-1">
              {offer.explanation.map((reason, idx) => (
                <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                  <span className="text-primary mt-1">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* System Note */}
          {offer.systemNote && (
            <div className="flex items-start gap-2 text-sm text-muted-foreground bg-muted/30 rounded-lg p-3">
              <Info className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{offer.systemNote}</span>
            </div>
          )}

          {/* Grace Period & Actions */}
          {isPending && !remaining.expired && (
            <>
              <Separator />
              <div className="space-y-3">
                <GracePeriodCountdown offer={offer} />
                
                <div className="flex gap-2">
                  {/* Accept Button */}
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button 
                        className="flex-1" 
                        disabled={isProcessing || hasAcceptedOffer}
                      >
                        <CheckCircle2 className="h-4 w-4 mr-2" />
                        Accept Offer
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Accept This Offer?</AlertDialogTitle>
                        <AlertDialogDescription className="space-y-2">
                          <p>You are about to accept the offer from <strong>{offer.companyName}</strong>.</p>
                          <div className="flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg mt-2">
                            <AlertTriangle className="h-5 w-5 text-amber-600 flex-shrink-0 mt-0.5" />
                            <p className="text-sm text-amber-700 dark:text-amber-400">
                              To preserve fairness, only one active acceptance is allowed. 
                              All other pending offers will be automatically expired.
                            </p>
                          </div>
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={() => onAccept(offer.offerId)}>
                          Confirm Accept
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>

                  {/* Decline Button */}
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" className="flex-1" disabled={isProcessing}>
                        <XCircle className="h-4 w-4 mr-2" />
                        Decline
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Decline This Offer?</AlertDialogTitle>
                        <AlertDialogDescription>
                          Are you sure you want to decline the offer from <strong>{offer.companyName}</strong>? 
                          This action cannot be undone.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction 
                          onClick={() => onDecline(offer.offerId)}
                          className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        >
                          Confirm Decline
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>

                {hasAcceptedOffer && (
                  <p className="text-xs text-muted-foreground text-center">
                    You have already accepted an offer. No further acceptances allowed.
                  </p>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
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
          <Clock className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="font-semibold text-lg mb-2">No Offers Yet</h3>
        <p className="text-muted-foreground max-w-sm">
          Aura will present offers here when companies express interest. 
          You'll be notified when new offers arrive.
        </p>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Offers() {
  const { toast } = useToast();
  const [offers, setOffers] = useState<Offer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);

  const hasAcceptedOffer = offers.some(o => o.status === 'accepted');
  const pendingOffers = offers.filter(o => o.status === 'pending');
  const pastOffers = offers.filter(o => o.status !== 'pending');

  useEffect(() => {
    const loadOffers = async () => {
      try {
        const data = await offerApi.getOffers();
        setOffers(data);
      } catch (error) {
        toast({
          title: 'Error loading offers',
          description: 'Please try again later',
          variant: 'destructive',
        });
      } finally {
        setIsLoading(false);
      }
    };
    loadOffers();
  }, [toast]);

  const handleAccept = async (offerId: string) => {
    setIsProcessing(true);
    try {
      await offerApi.acceptOffer(offerId);
      const updated = await offerApi.getOffers();
      setOffers(updated);
      toast({
        title: 'Offer Accepted',
        description: 'Congratulations! The company will contact you with next steps.',
      });
    } catch (error) {
      toast({
        title: 'Error accepting offer',
        description: error instanceof Error ? error.message : 'Please try again',
        variant: 'destructive',
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDecline = async (offerId: string) => {
    setIsProcessing(true);
    try {
      await offerApi.declineOffer(offerId);
      const updated = await offerApi.getOffers();
      setOffers(updated);
      toast({
        title: 'Offer Declined',
        description: 'You will continue to be considered for other opportunities.',
      });
    } catch (error) {
      toast({
        title: 'Error declining offer',
        description: error instanceof Error ? error.message : 'Please try again',
        variant: 'destructive',
      });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <StudentHeader />

      <main className="container max-w-3xl mx-auto px-4 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
              <Clock className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">Your Offers</h1>
              <p className="text-muted-foreground">
                System-proposed opportunities awaiting your decision
              </p>
            </div>
          </div>
        </div>

        {/* Fairness Notice */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6"
        >
          <div className="flex items-start gap-3 p-4 bg-primary/5 border border-primary/20 rounded-lg">
            <Shield className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium text-foreground mb-1">Fairness-First Matching</p>
              <p className="text-muted-foreground">
                Offers are system-generated. You cannot browse companies or rank preferences. 
                Respond within the grace period to maintain your position.
              </p>
            </div>
          </div>
        </motion.div>

        {isLoading ? (
          <Card>
            <CardContent className="py-16 text-center">
              <p className="text-muted-foreground">Loading offers...</p>
            </CardContent>
          </Card>
        ) : offers.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="space-y-8">
            {/* Pending Offers */}
            {pendingOffers.length > 0 && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold text-foreground">
                  Pending Decisions ({pendingOffers.length})
                </h2>
                {pendingOffers.map(offer => (
                  <OfferCard
                    key={offer.offerId}
                    offer={offer}
                    onAccept={handleAccept}
                    onDecline={handleDecline}
                    isProcessing={isProcessing}
                    hasAcceptedOffer={hasAcceptedOffer}
                  />
                ))}
              </div>
            )}

            {/* Past Offers */}
            {pastOffers.length > 0 && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold text-muted-foreground">
                  Past Offers ({pastOffers.length})
                </h2>
                {pastOffers.map(offer => (
                  <OfferCard
                    key={offer.offerId}
                    offer={offer}
                    onAccept={handleAccept}
                    onDecline={handleDecline}
                    isProcessing={isProcessing}
                    hasAcceptedOffer={hasAcceptedOffer}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Footer Notice */}
        <div className="mt-8 pt-6 border-t border-border">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Info className="h-4 w-4 flex-shrink-0" />
            <p>
              Offers are system-owned. Students cannot influence matching outcomes.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
