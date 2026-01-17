// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Notifications Page
 * 
 * BACKEND AUTHORITY MODEL:
 * - All notifications come from backend
 * - Frontend only renders and marks as read
 * - NO mock data or local state
 * 
 * OWNERSHIP: SYSTEM & COMPANY
 * STUDENT ACCESS: READ-ONLY
 */

import { useState, useEffect } from 'react';
import { Bell, Building2, Shield, Clock, CheckCheck, Inbox, AlertCircle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import StudentHeader from '@/components/StudentHeader';
import api from '@/utils/api';

// ============================================================================
// NOTIFICATION TYPES (SYSTEM-OWNED)
// ============================================================================

interface Notification {
  readonly id: string;
  readonly type: 'system' | 'company';
  readonly title: string;
  readonly message: string;
  readonly timestamp: string;
  readonly read: boolean;
}

// ============================================================================
// HELPER FUNCTIONS (DISPLAY ONLY)
// ============================================================================

function formatTimestamp(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffHours < 1) {
    return 'Just now';
  } else if (diffHours < 24) {
    return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  } else if (diffDays < 7) {
    return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
  } else {
    return date.toLocaleDateString('en-IN', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  }
}

// ============================================================================
// NOTIFICATION CARD COMPONENT
// ============================================================================

interface NotificationCardProps {
  notification: Notification;
}

function NotificationCard({ notification }: NotificationCardProps) {
  const isSystem = notification.type === 'system';
  
  return (
    <Card className={`transition-colors ${notification.read ? 'bg-muted/30' : 'bg-card border-primary/20'}`}>
      <CardContent className="p-4">
        <div className="flex gap-4">
          {/* Icon */}
          <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
            isSystem ? 'bg-primary/10 text-primary' : 'bg-secondary/50 text-secondary-foreground'
          }`}>
            {isSystem ? <Shield className="w-5 h-5" /> : <Building2 className="w-5 h-5" />}
          </div>
          
          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2 mb-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className={`font-medium ${notification.read ? 'text-muted-foreground' : 'text-foreground'}`}>
                  {notification.title}
                </h3>
                {!notification.read && (
                  <span className="w-2 h-2 rounded-full bg-primary flex-shrink-0" />
                )}
              </div>
              <Badge 
                variant={isSystem ? 'default' : 'secondary'}
                className="flex-shrink-0 text-xs"
              >
                {isSystem ? 'System' : 'Company'}
              </Badge>
            </div>
            
            <p className={`text-sm mb-2 ${notification.read ? 'text-muted-foreground' : 'text-foreground/80'}`}>
              {notification.message}
            </p>
            
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock className="w-3 h-3" />
              <span>{formatTimestamp(notification.timestamp)}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// EMPTY STATE COMPONENT
// ============================================================================

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mb-4">
        <Inbox className="w-8 h-8 text-muted-foreground" />
      </div>
      <h3 className="text-lg font-medium text-foreground mb-2">No updates yet</h3>
      <p className="text-sm text-muted-foreground max-w-sm">
        Aura will notify you when something changes in your matching journey.
      </p>
    </div>
  );
}

// ============================================================================
// LOADING SKELETON
// ============================================================================

function LoadingSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map((i) => (
        <Card key={i}>
          <CardContent className="p-4">
            <div className="flex gap-4">
              <Skeleton className="w-10 h-10 rounded-full" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-1/4" />
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Notifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isMarkingRead, setIsMarkingRead] = useState(false);
  
  const unreadCount = notifications.filter(n => !n.read).length;
  const hasNotifications = notifications.length > 0;

  /**
   * BACKEND-DRIVEN DATA FETCH
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   */
  useEffect(() => {
    const fetchNotifications = async () => {
      try {
        const response = await api.get<Notification[]>('/student/notifications');
        setNotifications(response.data);
      } catch {
        setError('Unable to load notifications. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchNotifications();
  }, []);

  /**
   * BACKEND-DRIVEN MARK ALL READ
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   */
  const handleMarkAllRead = async () => {
    setIsMarkingRead(true);
    try {
      await api.post('/student/notifications/mark-read');
      // Refetch to get authoritative state
      const response = await api.get<Notification[]>('/student/notifications');
      setNotifications(response.data);
    } catch {
      // Error handled silently - state remains unchanged
    } finally {
      setIsMarkingRead(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <StudentHeader />
        <main className="container max-w-2xl mx-auto px-4 py-8">
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
        <main className="container max-w-2xl mx-auto px-4 py-8">
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

  return (
    <div className="min-h-screen bg-background">
      <StudentHeader />
      
      <main className="container max-w-2xl mx-auto px-4 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                <Bell className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Notifications</h1>
                <p className="text-sm text-muted-foreground">
                  System and company updates related to your profile
                </p>
              </div>
            </div>
            
            {/* Unread count badge */}
            {unreadCount > 0 && (
              <Badge variant="default" className="text-sm">
                {unreadCount} unread
              </Badge>
            )}
          </div>
        </div>

        {/* Mark All Read Button */}
        {hasNotifications && unreadCount > 0 && (
          <div className="flex justify-end mb-4">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleMarkAllRead}
              disabled={isMarkingRead}
              className="text-muted-foreground hover:text-foreground"
            >
              <CheckCheck className="w-4 h-4 mr-2" />
              {isMarkingRead ? 'Updating...' : 'Mark all as read'}
            </Button>
          </div>
        )}

        {/* Notification List */}
        {hasNotifications ? (
          <div className="space-y-3">
            {notifications.map((notification) => (
              <NotificationCard key={notification.id} notification={notification} />
            ))}
          </div>
        ) : (
          <EmptyState />
        )}

        {/* Footer Notice */}
        <Separator className="my-8" />
        
        <div className="bg-muted/50 rounded-lg p-4 text-center">
          <div className="flex items-center justify-center gap-2 text-muted-foreground">
            <Shield className="w-4 h-4" />
            <p className="text-sm">
              All notifications are system or company generated. Students cannot respond to notifications.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
