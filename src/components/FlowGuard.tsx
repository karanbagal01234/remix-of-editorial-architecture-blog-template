// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useUI } from '@/context/UIContext';
import type { FlowStep } from '@/types/student';
import LoadingSkeleton from '@/components/LoadingSkeleton';

interface FlowGuardProps {
  children: React.ReactNode;
  step: FlowStep;
}

const FlowGuard: React.FC<FlowGuardProps> = ({ children, step }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, isFullyVerified, isInitialized } = useUI();
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    if (!isInitialized) return;

    // No user at all - redirect to login
    if (!user || !user.token) {
      navigate('/login', { state: { from: location }, replace: true });
      return;
    }

    // Check full verification for all student routes
    if (!isFullyVerified) {
      if (!user.emailVerified) {
        navigate('/verify/email', { state: { from: location }, replace: true });
        return;
      }
      if (!user.phoneVerified) {
        navigate('/verify/phone', { state: { from: location }, replace: true });
        return;
      }
    }

    const isProfileComplete = !!(user.name && user.email && user.phone && user.location);

    // Flow enforcement based on step
    switch (step) {
      case 'profile':
        setShouldRender(true);
        break;

      case 'skills':
        if (!isProfileComplete || user.status === 'profile-pending') {
          navigate('/student/profile', { state: { from: location }, replace: true });
          return;
        }
        setShouldRender(true);
        break;

      case 'preferences':
        if (!isProfileComplete || user.status === 'profile-pending') {
          navigate('/student/profile', { state: { from: location }, replace: true });
          return;
        }
        if (user.status === 'skills-pending') {
          navigate('/student/skill-extraction', { state: { from: location }, replace: true });
          return;
        }
        setShouldRender(true);
        break;

      case 'status':
        if (!isProfileComplete || user.status === 'profile-pending') {
          navigate('/student/profile', { state: { from: location }, replace: true });
          return;
        }
        if (user.status === 'skills-pending') {
          navigate('/student/skill-extraction', { state: { from: location }, replace: true });
          return;
        }
        if (user.status === 'preferences-pending') {
          navigate('/student/preferences', { state: { from: location }, replace: true });
          return;
        }
        setShouldRender(true);
        break;

      case 'result':
        if (!isProfileComplete || user.status === 'profile-pending') {
          navigate('/student/profile', { state: { from: location }, replace: true });
          return;
        }
        if (user.status === 'skills-pending') {
          navigate('/student/skill-extraction', { state: { from: location }, replace: true });
          return;
        }
        if (user.status === 'preferences-pending') {
          navigate('/student/preferences', { state: { from: location }, replace: true });
          return;
        }
        if (!user.matchResult) {
          navigate('/student/status', { state: { from: location }, replace: true });
          return;
        }
        setShouldRender(true);
        break;

      default:
        setShouldRender(true);
    }
  }, [isInitialized, user, isFullyVerified, step, navigate, location]);

  if (!isInitialized || !shouldRender) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <LoadingSkeleton lines={4} />
      </div>
    );
  }

  return <>{children}</>;
};

export default FlowGuard;
