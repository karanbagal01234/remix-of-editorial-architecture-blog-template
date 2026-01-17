import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import AIAvatar from './AIAvatar';

interface ChatMessageProps {
  content: string;
  isUser: boolean;
  animate?: boolean;
}

const ChatMessage: React.FC<ChatMessageProps> = ({ content, isUser, animate = true }) => {
  const [displayedText, setDisplayedText] = useState(animate && !isUser ? '' : content);
  const [isTyping, setIsTyping] = useState(animate && !isUser);

  useEffect(() => {
    if (!animate || isUser) return;

    let currentIndex = 0;
    setDisplayedText('');
    setIsTyping(true);

    const interval = setInterval(() => {
      if (currentIndex < content.length) {
        setDisplayedText(content.slice(0, currentIndex + 1));
        currentIndex++;
      } else {
        setIsTyping(false);
        clearInterval(interval);
      }
    }, 25);

    return () => clearInterval(interval);
  }, [content, animate, isUser]);

  return (
    <motion.div
      className={`flex gap-3 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
    >
      {/* Avatar */}
      <div className="flex-shrink-0">
        {isUser ? (
          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-secondary to-accent flex items-center justify-center">
            <span className="text-lg">👤</span>
          </div>
        ) : (
          <AIAvatar state={isTyping ? 'speaking' : 'idle'} size="sm" />
        )}
      </div>

      {/* Message bubble */}
      <motion.div
        className={`max-w-[75%] rounded-2xl px-4 py-3 ${
          isUser
            ? 'gradient-bg text-primary-foreground rounded-tr-sm'
            : 'glass rounded-tl-sm'
        }`}
        layout
      >
        <p className="text-sm leading-relaxed whitespace-pre-wrap">
          {displayedText}
          {isTyping && (
            <motion.span
              className="inline-block w-0.5 h-4 bg-current ml-0.5 align-middle"
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.5, repeat: Infinity }}
            />
          )}
        </p>
      </motion.div>
    </motion.div>
  );
};

export default ChatMessage;
