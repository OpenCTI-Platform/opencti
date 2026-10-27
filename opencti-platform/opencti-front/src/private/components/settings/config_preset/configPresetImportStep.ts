export type ConfigPresetImportSessionStatus = 'DRAFT' | 'APPLYING' | 'FINISHED' | 'INTERRUPTED';

// The screen of the wizard: the welcome choices, then the upload, the preview with the selection, the progress and the result
export type ConfigPresetImportStep = 'welcome' | 'upload' | 'preview' | 'progress' | 'interrupted' | 'result';

export interface ConfigPresetImportStepInput {
  // Status of the import session of the user, absent when there is none
  status: ConfigPresetImportSessionStatus | string | null | undefined;
  // The user chose to import a zip on the welcome screen
  hasChosenImport: boolean;
  // The uploaded zip no longer exists (a newer upload from another tab, or already imported): back to the upload
  isFileMissing: boolean;
  // The user's own import is running (the apply mutation is pending)
  isApplying: boolean;
}

// The step of the wizard, derived from the import session
export const getConfigPresetImportStep = ({ status, hasChosenImport, isFileMissing, isApplying }: ConfigPresetImportStepInput): ConfigPresetImportStep => {
  if (isApplying || status === 'APPLYING') {
    return 'progress';
  }
  if (isFileMissing) {
    return 'upload';
  }
  if (status === 'INTERRUPTED') {
    return 'interrupted';
  }
  if (status === 'DRAFT') {
    return 'preview';
  }
  if (status === 'FINISHED') {
    return 'result';
  }
  return hasChosenImport ? 'upload' : 'welcome';
};

// The name of the administrator whose import runs, in the data of a refusal because an import is running
export const getConfigPresetStartedBy = (error: unknown): string | undefined => {
  const errors = (error as { res?: { errors?: { extensions?: { data?: { started_by?: string } } }[] } })?.res?.errors;
  return errors?.[0]?.extensions?.data?.started_by;
};

// The reason of a refusal of the backend, read from extensions.data.reason and never from the message
export const getConfigPresetErrorReason = (error: unknown): string | undefined => {
  const errors = (error as { res?: { errors?: { extensions?: { data?: { reason?: string } } }[] } })?.res?.errors;
  return errors?.[0]?.extensions?.data?.reason;
};
