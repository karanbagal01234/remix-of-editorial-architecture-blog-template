// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React from 'react';
import { motion, Variants, Easing } from 'framer-motion';

type AvatarState = 'idle' | 'thinking' | 'speaking';

interface AIAvatarProps {
  state?: AvatarState;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

const sizeMap = {
  sm: 'w-12 h-12',
  md: 'w-20 h-20',
  lg: 'w-32 h-32',
  xl: 'w-48 h-48',
};

const easeInOut: Easing = 'easeInOut';
const easeOut: Easing = 'easeOut';
const linear: Easing = 'linear';

const AIAvatar: React.FC<AIAvatarProps> = ({ 
  state = 'idle', 
  size = 'md',
  className = '' 
}) => {
  // Animation variants for different states
  const containerVariants: Variants = {
    idle: {
      y: [0, -8, 0],
      transition: {
        duration: 3,
        repeat: Infinity,
        ease: easeInOut,
      },
    },
    thinking: {
      scale: [1, 1.05, 1],
      transition: {
        duration: 1.5,
        repeat: Infinity,
        ease: easeInOut,
      },
    },
    speaking: {
      y: [0, -4, 0, -2, 0],
      transition: {
        duration: 0.5,
        repeat: Infinity,
        ease: easeOut,
      },
    },
  };

  const glowVariants: Variants = {
    idle: {
      opacity: [0.4, 0.6, 0.4],
      scale: [1, 1.1, 1],
      transition: {
        duration: 4,
        repeat: Infinity,
        ease: easeInOut,
      },
    },
    thinking: {
      opacity: [0.5, 0.9, 0.5],
      scale: [1, 1.2, 1],
      transition: {
        duration: 1,
        repeat: Infinity,
        ease: easeInOut,
      },
    },
    speaking: {
      opacity: [0.6, 0.8, 0.6],
      scale: [1, 1.05, 1],
      transition: {
        duration: 0.3,
        repeat: Infinity,
        ease: easeOut,
      },
    },
  };

  const innerOrbVariants: Variants = {
    idle: {
      rotate: 360,
      transition: {
        duration: 20,
        repeat: Infinity,
        ease: linear,
      },
    },
    thinking: {
      rotate: 360,
      transition: {
        duration: 3,
        repeat: Infinity,
        ease: linear,
      },
    },
    speaking: {
      rotate: 360,
      transition: {
        duration: 5,
        repeat: Infinity,
        ease: linear,
      },
    },
  };

  return (
    <motion.div
      className={`relative ${sizeMap[size]} ${className}`}
      variants={containerVariants}
      animate={state}
    >
      {/* Outer glow effect */}
      <motion.div
        className="absolute inset-0 rounded-full bg-gradient-to-br from-primary via-secondary to-accent blur-xl"
        variants={glowVariants}
        animate={state}
      />

      {/* Main orb container */}
      <div className="relative w-full h-full rounded-full glass-strong overflow-hidden">
        {/* Gradient background */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/30 via-secondary/20 to-accent/30" />
        
        {/* Inner rotating orbs */}
        <motion.div
          className="absolute inset-2"
          variants={innerOrbVariants}
          animate={state}
        >
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-primary" />
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-secondary" />
          <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-accent" />
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-primary/70" />
        </motion.div>

        {/* Center core */}
        <div className="absolute inset-0 flex items-center justify-center">
          <motion.div
            className="w-1/3 h-1/3 rounded-full bg-gradient-to-br from-primary to-secondary"
            animate={{
              scale: state === 'thinking' ? [1, 1.2, 1] : state === 'speaking' ? [1, 0.9, 1] : 1,
            }}
            transition={{
              duration: state === 'thinking' ? 1 : 0.3,
              repeat: state !== 'idle' ? Infinity : 0,
            }}
          />
        </div>

        {/* Sparkle effects */}
        {state === 'speaking' && (
          <>
            <motion.div
              className="absolute top-1/4 right-1/4 w-1 h-1 rounded-full bg-card"
              animate={{ opacity: [0, 1, 0], scale: [0.5, 1.5, 0.5] }}
              transition={{ duration: 0.8, repeat: Infinity, delay: 0 }}
            />
            <motion.div
              className="absolute bottom-1/3 left-1/4 w-1 h-1 rounded-full bg-card"
              animate={{ opacity: [0, 1, 0], scale: [0.5, 1.5, 0.5] }}
              transition={{ duration: 0.8, repeat: Infinity, delay: 0.3 }}
            />
          </>
        )}
      </div>

      {/* Name label */}
      <motion.div
        className="absolute -bottom-6 left-1/2 -translate-x-1/2 text-xs font-medium text-muted-foreground"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        Aura
      </motion.div>
    </motion.div>
  );
};

export default AIAvatar;
