import React, { createContext, ReactNode, useCallback, useContext, useState } from 'react';
import { FileWithConnectors } from '@components/common/files/import_files/ImportFilesUploader';
import { graphql, PreloadedQuery } from 'react-relay';
import { ImportFilesContextQuery } from '@components/common/files/import_files/__generated__/ImportFilesContextQuery.graphql';
import { ImportFilesContextGuessMimeTypeQuery$data } from '@components/common/files/import_files/__generated__/ImportFilesContextGuessMimeTypeQuery.graphql';
import useGranted from '../../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { fetchQuery } from '../../../../../relay/environment';

export const importFilesQuery = graphql`
  query ImportFilesContextQuery($id: String!) {
    connectorsForImport {
      id
      name
      active
      auto
      only_contextual
      connector_scope
      updated_at
      configurations {
        id
        name
        configuration
      }
    }
    stixCoreObject(id: $id) {
      id
      entity_type
      ... on AttackPattern {
        name
        x_mitre_id
      }
      ... on Campaign {
        name
      }
      ... on CourseOfAction {
        name
      }
      ... on Note {
        attribute_abstract
        content
      }
      ... on ObservedData {
        name
      }
      ... on Opinion {
        opinion
      }
      ... on Report {
        name
      }
      ... on Grouping {
        name
      }
      ... on Individual {
        name
      }
      ... on Organization {
        name
      }
      ... on Sector {
        name
      }
      ... on System {
        name
      }
      ... on Indicator {
        name
      }
      ... on Infrastructure {
        name
      }
      ... on IntrusionSet {
        name
      }
      ... on Position {
        name
      }
      ... on City {
        name
      }
      ... on AdministrativeArea {
        name
      }
      ... on Country {
        name
      }
      ... on Region {
        name
      }
      ... on Malware {
        name
      }
      ... on MalwareAnalysis {
        result_name
      }
      ... on ThreatActor {
        name
      }
      ... on Tool {
        name
      }
      ... on Vulnerability {
        name
      }
      ... on Incident {
        name
      }
      ... on StixCyberObservable {
        observable_value
      }
      ... on StixFile {
        observableName: name
        x_opencti_additional_names
        hashes {
          algorithm
          hash
        }
      }
      ... on Event {
        name
      }
      ... on Case {
        name
      }
      ... on Task {
        name
      }
      ... on Channel {
        name
      }
      ... on Narrative {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Language {
        name
      }
    }
  }
`;

const importFilesContextGuessMimeTypeQuery = graphql`
  query ImportFilesContextGuessMimeTypeQuery($fileId: String!) {
    guessMimeType(fileId: $fileId)
  }
`;

export type ImportMode = 'auto' | 'manual' | 'form';
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
  selectedFormId?: string;
  setSelectedFormId: (formId?: string) => void;
  inDraftContext: boolean;
  guessMimeType: (fileId: string) => Promise<string | null>;
  queryRef: PreloadedQuery<ImportFilesContextQuery>;
};

const ImportFilesContext = createContext<ImportFilesContextProps | undefined>(undefined);

export const ImportFilesProvider = ({ children, initialValue }: {
  children: ReactNode;
  initialValue: InitialValues
}) => {
  const canSelectImportMode = useGranted(['KNOWLEDGE_KNASKIMPORT']); // Check capability to set connectors and validation mode
  const draftContext = useDraftContext();

  const [activeStep, setActiveStep] = useState(canSelectImportMode ? 0 : 1);
  const [importMode, setImportMode] = useState<ImportMode | undefined>(!canSelectImportMode ? 'auto' : undefined);
  const [files, setFiles] = useState<FileWithConnectors[]>([]);
  const [uploadStatus, setUploadStatus] = useState<undefined | UploadStatus>();
  const [draftId, setDraftId] = useState<string | undefined>(draftContext?.id);
  const [selectedFormId, setSelectedFormId] = useState<string | undefined>();
  const queryRef = useQueryLoading<ImportFilesContextQuery>(importFilesQuery, {
    id: initialValue.entityId || '',
  });

  const guessMimeType = useCallback(async (fileId: string): Promise<string | null> => {
    const result = await fetchQuery(
      importFilesContextGuessMimeTypeQuery,
      { fileId },
    ).toPromise() as ImportFilesContextGuessMimeTypeQuery$data;

    return result?.guessMimeType || null;
  }, []);

  return queryRef && (
    <React.Suspense>
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
          selectedFormId,
          setSelectedFormId,
          inDraftContext: !!draftContext?.id,
          guessMimeType,
          queryRef,
          ...initialValue,
        }}
      >
        {children}
      </ImportFilesContext.Provider>
    </React.Suspense>
  );
};

export const useImportFilesContext = () => {
  const context = useContext(ImportFilesContext);
  if (!context) {
    throw new Error('useImportFilesContext must be used within an ImportFilesProvider');
  }
  return context;
};
