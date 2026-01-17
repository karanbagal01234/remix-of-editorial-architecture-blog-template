import React from 'react';
import { motion } from 'framer-motion';

interface LoadingDotsProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeMap = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-3 h-3',
};

const LoadingDots: React.FC<LoadingDotsProps> = ({ size = 'md', className = '' }) => {
  const dotVariants = {
    initial: { y: 0 },
    animate: { y: [-4, 0, -4] },
  };

  return (
    <div className={`flex items-center gap-1.5 ${className}`}>
      {[0, 1, 2].map((index) => (
        <motion.div
          key={index}
          className={`${sizeMap[size]} rounded-full bg-primary`}
          variants={dotVariants}
          initial="initial"
          animate="animate"
          transition={{
            duration: 0.8,
            repeat: Infinity,
            delay: index * 0.15,
            ease: 'easeInOut',
          }}
        />
      ))}
    </div>
  );
};

export default LoadingDots;
