import React from 'react';
import { motion, Easing } from 'framer-motion';

interface LoadingSkeletonProps {
  className?: string;
  lines?: number;
  type?: 'text' | 'card' | 'avatar' | 'button';
}

const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({ 
  className = '', 
  lines = 1,
  type = 'text' 
}) => {
  const ease: Easing = 'linear';
  
  const shimmerProps = {
    animate: {
      backgroundPosition: ['200% 0', '-200% 0'],
    },
    transition: {
      duration: 1.5,
      repeat: Infinity,
      ease,
    },
  };

  if (type === 'card') {
    return (
      <motion.div
        className={`glass rounded-xl p-6 ${className}`}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <motion.div 
          className="h-4 w-1/3 rounded bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%] mb-4"
          {...shimmerProps}
        />
        <motion.div 
          className="h-8 w-2/3 rounded bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%] mb-4"
          {...shimmerProps}
        />
        <motion.div 
          className="h-3 w-full rounded bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%]"
          {...shimmerProps}
        />
      </motion.div>
    );
  }

  if (type === 'avatar') {
    return (
      <motion.div
        className={`w-12 h-12 rounded-full bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%] ${className}`}
        {...shimmerProps}
      />
    );
  }

  if (type === 'button') {
    return (
      <motion.div
        className={`h-10 w-32 rounded-lg bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%] ${className}`}
        {...shimmerProps}
      />
    );
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <motion.div
          key={i}
          className={`h-4 rounded bg-gradient-to-r from-muted via-muted-foreground/10 to-muted bg-[length:200%_100%] ${
            i === lines - 1 ? 'w-3/4' : 'w-full'
          }`}
          {...shimmerProps}
        />
      ))}
    </div>
  );
};

export default LoadingSkeleton;
