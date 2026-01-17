import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface FocusInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  icon?: React.ReactNode;
  error?: string;
}

const FocusInput: React.FC<FocusInputProps> = ({
  label,
  icon,
  error,
  className,
  ...props
}) => {
  const [isFocused, setIsFocused] = useState(false);

  return (
    <div className="relative w-full">
      {label && (
        <motion.label
          className="block text-sm font-medium text-muted-foreground mb-2"
          animate={{ color: isFocused ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))' }}
        >
          {label}
        </motion.label>
      )}
      
      <div className="relative">
        {icon && (
          <div className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground">
            {icon}
          </div>
        )}
        
        <motion.div
          className="absolute inset-0 rounded-xl opacity-0 pointer-events-none"
          animate={{
            opacity: isFocused ? 1 : 0,
            boxShadow: isFocused 
              ? '0 0 0 3px hsl(var(--primary) / 0.2), 0 0 20px hsl(var(--primary) / 0.15)'
              : '0 0 0 0px transparent',
          }}
          transition={{ duration: 0.2 }}
        />
        
        <input
          className={cn(
            'w-full px-4 py-3 rounded-xl border border-border bg-card/50 backdrop-blur-sm',
            'text-foreground placeholder:text-muted-foreground',
            'transition-all duration-200',
            'focus:outline-none focus:border-primary',
            icon && 'pl-12',
            error && 'border-destructive',
            className
          )}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          {...props}
        />
      </div>

      {error && (
        <motion.p
          className="text-sm text-destructive mt-1"
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
        >
          {error}
        </motion.p>
      )}
    </div>
  );
};

export default FocusInput;
