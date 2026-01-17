// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
// Student API - All logic is backend-authoritative
// Frontend NEVER computes skills, scores, or AI output

import api from '@/utils/api';
import type { UserData, UserPreferences } from '@/types/student';

// ============================================================================
// PROFILE APIs - Backend-authoritative
// ============================================================================

/**
 * Get student profile
 * Backend is the ONLY source of truth
 */
export const getStudentProfile = async (): Promise<UserData | null> => {
  try {
    const response = await api.get('/student/profile');
    return response.data;
  } catch (error) {
    return null;
  }
};

/**
 * Update student profile
 * Frontend sends data, backend validates and stores
 */
export const updateStudentProfile = async (data: Partial<UserData>): Promise<UserData> => {
  const response = await api.patch('/student/profile', data);
  return response.data;
};

// ============================================================================
// SKILL APIs - Backend-authoritative
// AI extraction happens on backend ONLY
// ============================================================================

/**
 * Request skill extraction from resume
 * Backend runs AI - frontend just displays results
 * Frontend NEVER parses resume or extracts skills
 */
export const extractSkillsFromResume = async (resumeId: string): Promise<string[]> => {
  const response = await api.post('/student/skills/extract', { resumeId });
  return response.data.skills;
};

/**
 * Confirm extracted skills
 * Student confirms or modifies, backend stores
 */
export const confirmSkills = async (skills: string[]): Promise<string[]> => {
  const response = await api.post('/student/skills/confirm', { skills });
  return response.data.skills;
};

// ============================================================================
// PREFERENCES APIs
// ============================================================================

/**
 * Update student preferences
 */
export const updatePreferences = async (prefs: UserPreferences): Promise<boolean> => {
  const response = await api.post('/student/preferences', prefs);
  return response.data.success;
};

/**
 * Get available domains for preference selection
 * Backend provides the list - frontend just displays
 */
export const getAvailableDomains = async (): Promise<string[]> => {
  const response = await api.get('/student/domains');
  return response.data.domains;
};
