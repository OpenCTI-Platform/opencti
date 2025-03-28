import React, { createContext, ReactNode, useContext, useState } from 'react';
import { FileWithConnectors } from '@components/common/files/import_files/ImportFilesUploader';
import useGranted from '../../../../../utils/hooks/useGranted';

export type ImportMode = 'auto' | 'manual';
export type UploadStatus = 'uploading' | 'success' | undefined;

interface InitialValues {
  entityId?: string;
}

type ImportFilesContextProps = InitialValues & {
  canSelectImportMode: boolean;
  activeStep: number;
  setActiveStep: (step: number) => void;
  importMode: ImportMode | undefined;
  setImportMode: (mode: ImportMode) => void;
  files: FileWithConnectors[];
  setFiles: (files: FileWithConnectors[]) => void;
  uploadStatus: UploadStatus;
  setUploadStatus: (uploadStatus: UploadStatus) => void;
  draftId?: string;
  setDraftId: (draftId?: string) => void;
};

const ImportFilesContext = createContext<ImportFilesContextProps | undefined>(undefined);

export const ImportFilesProvider = ({ children, initialValue }: {
  children: ReactNode;
  initialValue: InitialValues
}) => {
  const canSelectImportMode = useGranted(['KNOWLEDGE_KNASKIMPORT']); // Check capability to set connectors and validation mode

  const [activeStep, setActiveStep] = useState(canSelectImportMode ? 0 : 1);
  const [importMode, setImportMode] = useState<ImportMode | undefined>(!canSelectImportMode ? 'auto' : undefined);
  const [files, setFiles] = useState<FileWithConnectors[]>([]);
  const [uploadStatus, setUploadStatus] = useState<undefined | UploadStatus>();
  const [draftId, setDraftId] = useState<string | undefined>();

  return (
    <ImportFilesContext.Provider
      value={{
        canSelectImportMode,
        activeStep,
        setActiveStep,
        importMode,
        setImportMode,
        files,
        setFiles,
        uploadStatus,
        setUploadStatus,
        draftId,
        setDraftId,
        ...initialValue,
      }}
    >
      {children}
    </ImportFilesContext.Provider>
  );
};

export const useImportFilesContext = () => {
  const context = useContext(ImportFilesContext);
  if (!context) {
    throw new Error('useImportFilesContext must be used within an ImportFilesProvider');
  }
  return context;
};
