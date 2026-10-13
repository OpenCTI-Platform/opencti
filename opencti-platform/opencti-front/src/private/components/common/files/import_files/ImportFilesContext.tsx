import React, { createContext, ReactNode, useCallback, useContext, useEffect, useState } from 'react';
import { FileWithConnectors } from '@components/common/files/import_files/ImportFilesUploader';
import { graphql, PreloadedQuery } from 'react-relay';
import { ImportFilesContextQuery } from '@components/common/files/import_files/__generated__/ImportFilesContextQuery.graphql';
import { ImportFilesContextGuessMimeTypeQuery$data } from '@components/common/files/import_files/__generated__/ImportFilesContextGuessMimeTypeQuery.graphql';
import useGranted from '../../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import useImportAccess from '../../../../../utils/hooks/useImportAccess';
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
      xtm_one_intent
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

export interface InitialValues {
  entityId?: string;
  activeStep?: number;
  importMode?: ImportMode;
  initialFreeTextContent?: string;
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
  isForcedImportToDraft: boolean;
};

const ImportFilesContext = createContext<ImportFilesContextProps | undefined>(undefined);

// Without the right to import files there is no mode to choose: a form-only user fills forms, the others import automatically.
// The form-only default is only for the plain global dialog (top bar): a dialog opened for an entity or for pre-filled
// content (create unknown entities) is a file import and never lands on the forms.
export const getInitialImportMode = (
  canSelectImportMode: boolean,
  hasOnlyAccessToFormImport: boolean,
  initialValue: InitialValues,
): ImportMode | undefined => {
  if (canSelectImportMode) return initialValue.importMode;
  return hasOnlyAccessToFormImport && !initialValue.entityId && !initialValue.initialFreeTextContent ? 'form' : 'auto';
};

export const ImportFilesProvider = ({ children, initialValue }: {
  children: ReactNode;
  initialValue: InitialValues;
}) => {
  const canSelectImportMode = useGranted(['KNOWLEDGE_KNASKIMPORT'], false, { capabilitiesInDraft: ['KNOWLEDGE_KNASKIMPORT'] });
  const draftContext = useDraftContext();
  const { isForcedImportToDraft, hasOnlyAccessToFormImport } = useImportAccess();

  const initalActiveStep = initialValue.activeStep ?? (canSelectImportMode ? 0 : 1);
  const initialImportMode = getInitialImportMode(canSelectImportMode, hasOnlyAccessToFormImport, initialValue);

  const [activeStep, setActiveStep] = useState(initalActiveStep);
  const [importMode, setImportMode] = useState<ImportMode | undefined>(initialImportMode);
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
  useEffect(() => {
    setActiveStep(initalActiveStep);
    setImportMode(initialImportMode);
  }, [initialValue.activeStep, initialValue.importMode]);

  return queryRef && (
    <React.Suspense>
      <ImportFilesContext.Provider
        value={{
          ...initialValue,
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
          isForcedImportToDraft,
          guessMimeType,
          queryRef,
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
