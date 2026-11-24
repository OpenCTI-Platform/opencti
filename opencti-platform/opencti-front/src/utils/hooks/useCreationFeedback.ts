import { createContext } from 'react';

export interface CreationFeedback {
  /**
   * When true, a creation mutation (`<type>Add`) sent through `useApiMutation` does not show its own success message:
   * the surrounding view (e.g. a container's add panel) gives a single confirmation instead.
   */
  silenceCreationSuccess: boolean;
}

export const CreationFeedbackContext = createContext<CreationFeedback>({ silenceCreationSuccess: false });
