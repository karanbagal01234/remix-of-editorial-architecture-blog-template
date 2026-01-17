/**
 * FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
 * 
 * Resume API
 * 
 * Handles resume versioning and skill extraction.
 * All state is backend-authoritative. Frontend only sends intent and renders outcome.
 * 
 * BACKEND CONTRACT:
 * - GET  /api/resumes/history        → ResumeHistory
 * - POST /api/resumes/upload         → ResumeVersion (multipart/form-data)
 * - POST /api/resumes/:id/extract    → { skills: string[] }
 * - POST /api/resumes/:id/confirm    → ResumeVersion
 * - GET  /api/matches/:matchId/resume-version → { version: number; uploadedAt: string }
 */

import api from '@/utils/api';
import type { ResumeVersion, ResumeHistory } from '@/types/aura';

// ============================================================================
// API FUNCTIONS — BACKEND-READY HTTP STUBS
// ============================================================================

/**
 * Fetches the complete resume history (current + archived versions).
 */
export const getResumeHistory = async (): Promise<ResumeHistory> => {
  const response = await api.get<ResumeHistory>('/api/resumes/history');
  return response.data;
};

/**
 * Uploads a new resume file.
 * 
 * BACKEND AUTHORITY:
 * - Backend archives current version
 * - Backend increments version number
 * - Backend generates resumeId
 * - Backend stores file securely
 * 
 * FRONTEND RESPONSIBILITY:
 * - Send file via multipart/form-data
 * - Show upload progress if needed
 * - Handle errors gracefully
 */
export const uploadResume = async (file: File): Promise<ResumeVersion> => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await api.post<ResumeVersion>('/api/resumes/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

/**
 * Triggers skill extraction for a resume.
 * 
 * BACKEND AUTHORITY:
 * - Backend runs AI/NLP extraction
 * - Backend updates resume status
 * - Frontend treats extracted skills as opaque backend data
 * 
 * FRONTEND RESPONSIBILITY:
 * - Show loading state during extraction
 * - Display backend-provided skills
 * - DO NOT run any skill parsing/extraction locally
 */
export const extractSkillsFromResume = async (
  resumeId: string
): Promise<string[]> => {
  const response = await api.post<{ skills: string[] }>(
    `/api/resumes/${resumeId}/extract`
  );
  return response.data.skills;
};

/**
 * Confirms/modifies the extracted skills for a resume.
 * 
 * BACKEND AUTHORITY:
 * - Backend validates skills
 * - Backend marks skills as confirmed
 * - Backend updates resume status to active
 * 
 * FRONTEND RESPONSIBILITY:
 * - Allow user to review/edit skills
 * - Send confirmed skill list to backend
 */
export const confirmSkills = async (
  resumeId: string,
  confirmedSkills: string[]
): Promise<ResumeVersion> => {
  const response = await api.post<ResumeVersion>(
    `/api/resumes/${resumeId}/confirm`,
    { skills: confirmedSkills }
  );
  return response.data;
};

/**
 * Gets the resume version used for a specific match.
 * 
 * Used for match explainability — shows which resume version
 * was active when the match was created.
 */
export const getResumeVersionForMatch = async (
  matchId: string
): Promise<{ version: number; uploadedAt: string }> => {
  const response = await api.get<{ version: number; uploadedAt: string }>(
    `/api/matches/${matchId}/resume-version`
  );
  return response.data;
};
