import { createContext } from 'react';

/**
 * Lets a bulk creation (several objects created from one form) and the surrounding view share their feedback:
 * the bulk result dialog already confirms the creation, so the view adds its own line to it instead of a message.
 */
export interface BulkCreationFeedback {
  // A bulk creation starts: called only when several objects are created at once
  onBulkStart: () => void;
  // All its creations are done, successfully or not
  onBulkCompleted: () => void;
  // Its result dialog is closed
  onBulkEnd: () => void;
  // Translated name of the container the objects are added to, e.g. "Report"
  containerType: string;
  // Progress of the objects' add to the container: the result dialog cannot be closed while it is in progress
  progress: { done: number; total: number; inProgress: boolean } | null;
  // The line the view adds to the bulk result once done, e.g. "3 entities added to the Report"
  resultMessage: string | null;
}

export interface CreationFeedback {
  /**
   * When true, a creation mutation (`<type>Add`) sent through `useApiMutation` does not show its own success message:
   * the surrounding view (e.g. a container's add panel) gives a single confirmation instead.
   */
  silenceCreationSuccess: boolean;
  bulkCreation?: BulkCreationFeedback;
}

export const CreationFeedbackContext = createContext<CreationFeedback>({ silenceCreationSuccess: false });
