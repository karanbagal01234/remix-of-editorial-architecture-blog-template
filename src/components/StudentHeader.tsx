// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
/**
 * Student Header Component
 * 
 * BACKEND AUTHORITY MODEL:
 * - Unread count comes from backend via user context
 * - Frontend only renders backend-provided state
 * - NO mock data
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { LogOut, User, Home, Loader2, Bell } from 'lucide-react';
import { useUI } from '@/context/UIContext';
import AnimatedButton from './AnimatedButton';
import { Badge } from '@/components/ui/badge';
import api from '@/utils/api';

interface NotificationCount {
  unread: number;
}

const StudentHeader: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useUI();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  /**
   * BACKEND-DRIVEN NOTIFICATION COUNT
   * 
   * FRONTEND FROZEN — BACKEND AUTHORITY REQUIRED
   */
  useEffect(() => {
    const fetchUnreadCount = async () => {
      try {
        const response = await api.get<NotificationCount>('/student/notifications/unread-count');
        setUnreadCount(response.data.unread);
      } catch {
        // Silently fail - count stays at 0
      }
    };

    fetchUnreadCount();
  }, []);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
      await logout();
      navigate('/', { replace: true });
    } catch (err) {
      console.error('Logout failed:', err);
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <motion.header
      className="glass-strong rounded-2xl p-4 mb-6 flex items-center justify-between"
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="flex items-center gap-3">
        <Link to="/" className="p-2 rounded-lg hover:bg-muted transition-colors">
          <Home className="w-5 h-5 text-muted-foreground" />
        </Link>
        <div className="h-6 w-px bg-border" />
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
            <User className="w-4 h-4 text-primary" />
          </div>
          <div className="hidden sm:block">
            <p className="text-sm font-medium leading-none">
              {user?.name || 'Student'}
            </p>
            <p className="text-xs text-muted-foreground">
              {user?.email || 'Not set'}
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* Notification Bell */}
        <Link
          to="/student/notifications"
          className="relative p-2 rounded-lg hover:bg-muted transition-colors"
          aria-label="Notifications"
        >
          <Bell className="w-5 h-5 text-muted-foreground" />
          {unreadCount > 0 && (
            <Badge
              variant="default"
              className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center text-xs"
            >
              {unreadCount > 9 ? '9+' : unreadCount}
            </Badge>
          )}
        </Link>

        <AnimatedButton
          variant="outline"
          size="sm"
          onClick={handleLogout}
          disabled={isLoggingOut}
        >
          {isLoggingOut ? (
            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
          ) : (
            <LogOut className="w-4 h-4 mr-2" />
          )}
          {isLoggingOut ? 'Logging out...' : 'Logout'}
        </AnimatedButton>
      </div>
    </motion.header>
  );
};

export default StudentHeader;
