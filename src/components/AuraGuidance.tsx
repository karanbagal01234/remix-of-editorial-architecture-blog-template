// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import AIAvatar from './AIAvatar';
import { X } from 'lucide-react';

interface AuraGuidanceProps {
  message: string;
  isVisible?: boolean;
  onClose?: () => void;
}

const AuraGuidance: React.FC<AuraGuidanceProps> = ({ 
  message, 
  isVisible = true,
  onClose 
}) => {
  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          className="fixed bottom-6 left-6 z-50 flex items-end gap-3 max-w-sm"
          initial={{ opacity: 0, y: 50, scale: 0.8 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 50, scale: 0.8 }}
          transition={{ type: 'spring', stiffness: 300, damping: 25 }}
        >
          <AIAvatar state="speaking" size="md" />
          <motion.div
            className="glass-strong rounded-2xl rounded-bl-md p-4 relative"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
          >
            {onClose && (
              <button
                onClick={onClose}
                className="absolute -top-2 -right-2 p-1 rounded-full bg-muted hover:bg-muted/80 transition-colors"
              >
                <X className="w-3 h-3" />
              </button>
            )}
            <p className="text-sm text-foreground leading-relaxed">{message}</p>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default AuraGuidance;
