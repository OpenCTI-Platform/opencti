import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import { Alert, Spinner } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { ConfigPresetImportWizardApplyMutation } from './__generated__/ConfigPresetImportWizardApplyMutation.graphql';
import { ConfigPresetImportWizardClearMutation } from './__generated__/ConfigPresetImportWizardClearMutation.graphql';
import { ConfigPresetImportWizardQuery, ConfigPresetImportWizardQuery$data } from './__generated__/ConfigPresetImportWizardQuery.graphql';
import { getConfigPresetErrorReason, getConfigPresetImportStep } from './configPresetImportStep';
import ConfigPresetImportPreview from './ConfigPresetImportPreview';
import { ConfigPresetImportProgress, ConfigPresetImportResult } from './ConfigPresetImportResult';
import ConfigPresetImportUpload from './ConfigPresetImportUpload';
import ConfigPresetWizardWelcome from './ConfigPresetWizardWelcome';

const configPresetImportWizardQuery = graphql`
  query ConfigPresetImportWizardQuery {
    configPresetImportSession {
      status
      file_id
      revision
      selections {
        type
        items
        excluded_items
      }
      total
      results {
        type
        key
        status
        reason
      }
      outcome
      counts {
        created
        overwritten
        skipped
        failed
      }
      report_id
      available_events
    }
  }
`;

// The mutation returns the settings, so that the store learns completed, the theme, the title and the whitemark
const configPresetImportWizardApplyMutation = graphql`
  mutation ConfigPresetImportWizardApplyMutation($file_id: String!, $selections: [ConfigPresetSelectionInput!]!) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: false) {
      report_id
      settings {
        ...RootSettings
      }
    }
  }
`;

const configPresetImportWizardClearMutation = graphql`
  mutation ConfigPresetImportWizardClearMutation($delete_file: Boolean) {
    configPresetImportSessionClear(delete_file: $delete_file)
  }
`;

export type ConfigPresetImportSession = NonNullable<ConfigPresetImportWizardQuery$data['configPresetImportSession']>;

interface ConfigPresetImportWizardProps {
  // Closes the wizard once a finished import is closed
  onFinish: () => void;
}

// The import steps of the wizard: the step is derived from the import session of the user, kept on the backend
const ConfigPresetImportWizard: FunctionComponent<ConfigPresetImportWizardProps> = ({ onFinish }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const environment = useRelayEnvironment();
  // undefined: not read yet, null: no session
  const [session, setSession] = useState<ConfigPresetImportSession | null | undefined>(undefined);
  const [hasChosenImport, setHasChosenImport] = useState(false);
  const [isFileMissing, setIsFileMissing] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [commitApply] = useApiMutation<ConfigPresetImportWizardApplyMutation>(configPresetImportWizardApplyMutation);
  const [commitClear] = useApiMutation<ConfigPresetImportWizardClearMutation>(configPresetImportWizardClearMutation);

  const refresh = useCallback(() => {
    return fetchQuery<ConfigPresetImportWizardQuery>(environment, configPresetImportWizardQuery, {}, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => setSession(data?.configPresetImportSession ?? null))
      // The global toast shows the error, the wizard keeps what it shows
      .catch(() => undefined);
  }, [environment]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const step = getConfigPresetImportStep({ status: session?.status, hasChosenImport, isFileMissing, isApplying });

  // Progress: the session is read every five seconds while the import runs, and the polling stops with the step or on close
  useEffect(() => {
    if (step !== 'progress') {
      return undefined;
    }
    const interval = window.setInterval(refresh, FIVE_SECONDS);
    return () => window.clearInterval(interval);
  }, [step, refresh]);

  const handleApply = (fileId: string, selections: ConfigPresetImportWizardApplyMutation['variables']['selections']) => {
    setIsApplying(true);
    commitApply({
      variables: { file_id: fileId, selections },
      onCompleted: () => {
        setIsApplying(false);
        refresh();
      },
      onError: (error) => {
        setIsApplying(false);
        if (getConfigPresetErrorReason(error) === 'file_missing') {
          setIsFileMissing(true);
        }
        refresh();
      },
    });
  };

  const handleStartOver = () => {
    commitClear({
      variables: { delete_file: true },
      onCompleted: () => {
        setSession(null);
        setIsFileMissing(false);
        setHasChosenImport(true);
      },
    });
  };

  const handleClose = () => {
    commitClear({ variables: { delete_file: false }, onCompleted: onFinish });
  };

  if (session === undefined) {
    return <Spinner label={t_i18n('Loading')} />;
  }
  if (step === 'welcome') {
    return <ConfigPresetWizardWelcome onImport={() => setHasChosenImport(true)} />;
  }
  if (step === 'upload') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        {isFileMissing && (
          <Alert severity="warning" title={t_i18n('The uploaded file no longer exists')} description={t_i18n('Upload the configuration bundle again.')} />
        )}
        <ConfigPresetImportUpload onUploaded={() => {
          setIsFileMissing(false);
          refresh();
        }}
        />
      </div>
    );
  }
  if (step === 'progress') {
    return <ConfigPresetImportProgress session={session} />;
  }
  if (step === 'result' && session) {
    return <ConfigPresetImportResult session={session} onClose={handleClose} />;
  }
  return (
    <ConfigPresetImportPreview
      key={session?.file_id}
      session={session!}
      onApply={(selections) => handleApply(session!.file_id, selections)}
      onStartOver={handleStartOver}
      onFileMissing={() => setIsFileMissing(true)}
    />
  );
};

export default ConfigPresetImportWizard;
