// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  Sparkles,
  Sliders,
  ToggleLeft,
  ToggleRight,
  Save,
  RefreshCw,
} from 'lucide-react';
import AnimatedButton from '@/components/AnimatedButton';
import AIAvatar from '@/components/AIAvatar';
import { toast } from '@/hooks/use-toast';

interface PolicySetting {
  id: string;
  label: string;
  description: string;
  type: 'slider' | 'toggle';
  value: number | boolean;
  min?: number;
  max?: number;
  step?: number;
}

const PolicySimulator: React.FC = () => {
  const [settings, setSettings] = useState<PolicySetting[]>([
    {
      id: 'skill_weight',
      label: 'Skill Match Weight',
      description: 'How much importance to give to skill matching',
      type: 'slider',
      value: 70,
      min: 0,
      max: 100,
      step: 5,
    },
    {
      id: 'gpa_weight',
      label: 'GPA Weight',
      description: 'Importance of academic performance in matching',
      type: 'slider',
      value: 40,
      min: 0,
      max: 100,
      step: 5,
    },
    {
      id: 'location_preference',
      label: 'Location Preference',
      description: 'Weight given to location-based matching',
      type: 'slider',
      value: 30,
      min: 0,
      max: 100,
      step: 5,
    },
    {
      id: 'experience_required',
      label: 'Experience Threshold (months)',
      description: 'Minimum experience required for matching',
      type: 'slider',
      value: 6,
      min: 0,
      max: 24,
      step: 1,
    },
    {
      id: 'auto_match',
      label: 'Auto-Match Enabled',
      description: 'Automatically match students when score exceeds threshold',
      type: 'toggle',
      value: true,
    },
    {
      id: 'notify_companies',
      label: 'Notify Companies',
      description: 'Send notifications to companies for new matches',
      type: 'toggle',
      value: true,
    },
    {
      id: 'include_pending',
      label: 'Include Pending Applications',
      description: 'Consider pending applications in matching algorithm',
      type: 'toggle',
      value: false,
    },
    {
      id: 'diversity_boost',
      label: 'Diversity Boost',
      description: 'Apply diversity-focused matching enhancements',
      type: 'toggle',
      value: true,
    },
  ]);

  const [hasChanges, setHasChanges] = useState(false);

  const handleSliderChange = (id: string, value: number) => {
    setSettings((prev) =>
      prev.map((s) => (s.id === id ? { ...s, value } : s))
    );
    setHasChanges(true);
  };

  const handleToggleChange = (id: string) => {
    setSettings((prev) =>
      prev.map((s) => (s.id === id ? { ...s, value: !s.value } : s))
    );
    setHasChanges(true);
  };

  const handleSave = () => {
    toast({
      title: 'Settings Saved',
      description: 'Your policy settings have been updated successfully.',
    });
    setHasChanges(false);
  };

  const handleReset = () => {
    setSettings((prev) =>
      prev.map((s) => ({
        ...s,
        value: s.type === 'slider' ? 50 : true,
      }))
    );
    setHasChanges(true);
  };

  const sliderSettings = settings.filter((s) => s.type === 'slider');
  const toggleSettings = settings.filter((s) => s.type === 'toggle');

  return (
    <div className="min-h-screen">
      {/* Header */}
      <motion.header
        className="glass-strong border-b border-border sticky top-0 z-40"
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
      >
        <div className="container mx-auto px-4 py-4 flex items-center gap-4">
          <Link
            to="/dashboard"
            className="p-2 rounded-xl hover:bg-muted transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>

          <div className="flex items-center gap-3 flex-1">
            <div className="w-10 h-10 rounded-xl gradient-bg flex items-center justify-center text-primary-foreground">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-semibold">Policy Simulator</h1>
              <p className="text-sm text-muted-foreground">
                Configure matching algorithms
              </p>
            </div>
          </div>

          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg gradient-bg flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-primary-foreground" />
            </div>
          </Link>
        </div>
      </motion.header>

      <main className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Aura Insight */}
        <motion.div
          className="glass rounded-2xl p-6 mb-8 flex items-start gap-4"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <AIAvatar state="idle" size="md" />
          <div>
            <h2 className="font-semibold mb-1">Aura's Policy Advice</h2>
            <p className="text-muted-foreground text-sm">
              "Based on current market trends, I'd recommend increasing skill
              match weight to 75% and enabling diversity boost. This tends to
              produce more successful long-term placements!"
            </p>
          </div>
        </motion.div>

        {/* Sliders Section */}
        <motion.section
          className="mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-primary" />
            Weight Settings
          </h2>

          <div className="grid gap-6">
            {sliderSettings.map((setting, index) => (
              <motion.div
                key={setting.id}
                className="glass rounded-2xl p-6"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 + index * 0.05 }}
              >
                <div className="flex items-center justify-between mb-2">
                  <label className="font-medium">{setting.label}</label>
                  <span className="text-lg font-bold gradient-text">
                    {setting.value as number}
                    {setting.id !== 'experience_required' && '%'}
                    {setting.id === 'experience_required' && ' mo'}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  {setting.description}
                </p>
                <input
                  type="range"
                  min={setting.min}
                  max={setting.max}
                  step={setting.step}
                  value={setting.value as number}
                  onChange={(e) =>
                    handleSliderChange(setting.id, parseInt(e.target.value))
                  }
                  className="w-full h-2 bg-muted rounded-full appearance-none cursor-pointer accent-primary"
                  style={{
                    background: `linear-gradient(to right, hsl(var(--primary)) ${
                      ((setting.value as number) - (setting.min || 0)) /
                      ((setting.max || 100) - (setting.min || 0)) *
                      100
                    }%, hsl(var(--muted)) ${
                      ((setting.value as number) - (setting.min || 0)) /
                      ((setting.max || 100) - (setting.min || 0)) *
                      100
                    }%)`,
                  }}
                />
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>{setting.min}</span>
                  <span>{setting.max}</span>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* Toggles Section */}
        <motion.section
          className="mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <ToggleRight className="w-5 h-5 text-primary" />
            Feature Toggles
          </h2>

          <div className="glass rounded-2xl divide-y divide-border">
            {toggleSettings.map((setting, index) => (
              <motion.div
                key={setting.id}
                className="p-4 flex items-center justify-between"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.35 + index * 0.05 }}
              >
                <div>
                  <label className="font-medium">{setting.label}</label>
                  <p className="text-sm text-muted-foreground">
                    {setting.description}
                  </p>
                </div>
                <button
                  onClick={() => handleToggleChange(setting.id)}
                  className="relative w-14 h-8 rounded-full transition-colors"
                  style={{
                    backgroundColor: setting.value
                      ? 'hsl(var(--primary))'
                      : 'hsl(var(--muted))',
                  }}
                >
                  <motion.div
                    className="absolute top-1 w-6 h-6 rounded-full bg-card shadow-md"
                    animate={{ left: setting.value ? 'calc(100% - 28px)' : '4px' }}
                    transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                  />
                </button>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* Action Buttons */}
        <motion.div
          className="flex flex-col sm:flex-row gap-4 sticky bottom-4"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <AnimatedButton
            variant="outline"
            onClick={handleReset}
            className="flex-1"
          >
            <RefreshCw className="mr-2 w-5 h-5" />
            Reset to Defaults
          </AnimatedButton>
          <AnimatedButton
            onClick={handleSave}
            className="flex-1"
            disabled={!hasChanges}
          >
            <Save className="mr-2 w-5 h-5" />
            Save Changes
          </AnimatedButton>
        </motion.div>

        {/* Disclaimer */}
        <p className="text-xs text-muted-foreground text-center mt-8 p-4 rounded-xl bg-muted/30">
          ⚠️ This is a UI simulation for demonstration purposes. Changes will not
          affect actual matching algorithms.
        </p>
      </main>
    </div>
  );
};

export default PolicySimulator;
