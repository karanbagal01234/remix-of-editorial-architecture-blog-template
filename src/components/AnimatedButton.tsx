// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { forwardRef } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface AnimatedButtonProps {
  variant?: 'primary' | 'secondary' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
  isLoading?: boolean;
  className?: string;
  disabled?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
}

const variantStyles = {
  primary: 'gradient-bg text-primary-foreground shadow-lg hover:shadow-xl',
  secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
  ghost: 'bg-transparent hover:bg-muted text-foreground',
  outline: 'border-2 border-primary text-primary hover:bg-primary hover:text-primary-foreground',
};

const sizeStyles = {
  sm: 'px-4 py-2 text-sm',
  md: 'px-6 py-3 text-base',
  lg: 'px-8 py-4 text-lg',
};

const AnimatedButton = forwardRef<HTMLButtonElement, AnimatedButtonProps>(({
  variant = 'primary',
  size = 'md',
  children,
  isLoading = false,
  className,
  disabled,
  onClick,
  type = 'button',
}, ref) => {
  return (
    <motion.button
      ref={ref}
      type={type}
      className={cn(
        'relative rounded-xl font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed',
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
      whileHover={{ scale: disabled ? 1 : 1.02 }}
      whileTap={{ scale: disabled ? 1 : 0.98 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
      disabled={disabled || isLoading}
      onClick={onClick}
    >
      {isLoading ? (
        <span className="flex items-center justify-center gap-2">
          <motion.span
            className="w-4 h-4 border-2 border-current border-t-transparent rounded-full"
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          />
          Loading...
        </span>
      ) : (
        children
      )}
    </motion.button>
  );
});

AnimatedButton.displayName = 'AnimatedButton';

export default AnimatedButton;
