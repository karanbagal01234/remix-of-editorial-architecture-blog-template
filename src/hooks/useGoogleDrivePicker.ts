/**
 * Google Drive Picker Hook
 * 
 * RULES:
 * - Google Drive = input source only
 * - Frontend sends file metadata/reference to backend
 * - Backend handles: fetching, parsing, skill extraction, versioning
 * - Frontend MUST NOT parse resumes or extract skills
 */

import { useState, useCallback } from 'react';
import api from '@/utils/api';
import { toast } from 'sonner';
import { ResumeVersionSchema } from '@/schemas/api.schemas';
import type { ResumeVersion } from '@/types/aura';

interface GoogleDriveFile {
  id: string;
  name: string;
  mimeType: string;
  webViewLink?: string;
}

interface UseGoogleDrivePickerReturn {
  isLoading: boolean;
  openPicker: () => void;
  submitFromDrive: (file: GoogleDriveFile) => Promise<ResumeVersion | null>;
}

export const useGoogleDrivePicker = (): UseGoogleDrivePickerReturn => {
  const [isLoading, setIsLoading] = useState(false);

  /**
   * Open Google Drive picker
   * Backend provides OAuth URL for picker integration
   */
  const openPicker = useCallback(() => {
    const apiUrl = import.meta.env.VITE_API_URL || '/api';
    const redirectUrl = `${window.location.origin}/student/skill-extraction?source=gdrive`;
    
    // Redirect to backend's Google Drive OAuth flow
    window.location.href = `${apiUrl}/oauth/google-drive/picker?redirect_uri=${encodeURIComponent(redirectUrl)}`;
  }, []);

  /**
   * Submit Google Drive file reference to backend
   * Backend will fetch and process the file
   */
  const submitFromDrive = useCallback(async (file: GoogleDriveFile): Promise<ResumeVersion | null> => {
    setIsLoading(true);
    
    try {
      const response = await api.post('/api/resumes/upload/gdrive', {
        fileId: file.id,
        fileName: file.name,
        mimeType: file.mimeType,
      });
      
      const validated = ResumeVersionSchema.safeParse(response.data);
      
      if (!validated.success) {
        toast.error('Invalid resume response format');
        return null;
      }
      
      toast.success('Resume uploaded successfully');
      return validated.data as ResumeVersion;
    } catch (error) {
      toast.error('Failed to upload resume from Google Drive');
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  return {
    isLoading,
    openPicker,
    submitFromDrive,
  };
};

export default useGoogleDrivePicker;
