import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import { Alert, Spinner } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { FIVE_SECONDS } from '../../../../../utils/Time';
import { ConfigPresetImportWizardApplyMutation } from './__generated__/ConfigPresetImportWizardApplyMutation.graphql';
import { ConfigPresetImportWizardClearMutation } from './__generated__/ConfigPresetImportWizardClearMutation.graphql';
import { ConfigPresetImportWizardQuery, ConfigPresetImportWizardQuery$data } from './__generated__/ConfigPresetImportWizardQuery.graphql';
import { ConfigPresetImportWizardBackMutation } from './__generated__/ConfigPresetImportWizardBackMutation.graphql';
import { ConfigPresetImportWizardRunningQuery, ConfigPresetImportWizardRunningQuery$data } from './__generated__/ConfigPresetImportWizardRunningQuery.graphql';
import { getConfigPresetErrorReason, getConfigPresetImportStep, getConfigPresetStartedBy } from './configPresetImportStep';
import ConfigPresetImportInterrupted from './ConfigPresetImportInterrupted';
import ConfigPresetImportPreview, { ConfigPresetImportPreviewProps } from './ConfigPresetImportPreview';
import { ConfigPresetImportProgress, ConfigPresetImportResult } from './ConfigPresetImportResult';
import ConfigPresetImportUpload from './ConfigPresetImportUpload';
import ConfigPresetWizardStepper from '../ConfigPresetWizardStepper';
import ConfigPresetWizardWelcome from '../ConfigPresetWizardWelcome';

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
        mode
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

// The same document applies and simulates. The real import returns the settings, so that the store learns completed, the
// theme and the title; a dry run returns them null and writes nothing.
const configPresetImportWizardApplyMutation = graphql`
  mutation ConfigPresetImportWizardApplyMutation($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean!) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results {
        type
        key
        status
        reason
      }
      report_id
      settings {
        ...RootSettings
      }
    }
  }
`;

// The import that runs on the platform, read from its running record: the other administrators see who runs it
const configPresetImportWizardRunningQuery = graphql`
  query ConfigPresetImportWizardRunningQuery {
    configPresetImportRunning {
      running {
        name
        is_mine
        processed
        total
      }
      last_finished_at
    }
  }
`;

const configPresetImportWizardBackMutation = graphql`
  mutation ConfigPresetImportWizardBackMutation {
    configPresetImportSessionBackToSelection {
      status
    }
  }
`;

const configPresetImportWizardClearMutation = graphql`
  mutation ConfigPresetImportWizardClearMutation($delete_file: Boolean) {
    configPresetImportSessionClear(delete_file: $delete_file)
  }
`;

export type ConfigPresetImportSession = NonNullable<ConfigPresetImportWizardQuery$data['configPresetImportSession']>;
type ConfigPresetImportRunning = ConfigPresetImportWizardRunningQuery$data['configPresetImportRunning'];

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
  const [running, setRunning] = useState<ConfigPresetImportRunning | null>(null);
  // The administrator whose import refused the last Apply
  const [startedBy, setStartedBy] = useState<string | null>(null);
  const [commitApply] = useApiMutation<ConfigPresetImportWizardApplyMutation>(configPresetImportWizardApplyMutation);
  const [commitClear] = useApiMutation<ConfigPresetImportWizardClearMutation>(configPresetImportWizardClearMutation);
  const [commitBack] = useApiMutation<ConfigPresetImportWizardBackMutation>(configPresetImportWizardBackMutation);

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

  // The running import is read every five seconds while the wizard is open: closing it unmounts the effect and stops the polling
  const refreshRunning = useCallback(() => {
    return fetchQuery<ConfigPresetImportWizardRunningQuery>(environment, configPresetImportWizardRunningQuery, {}, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => setRunning(data?.configPresetImportRunning ?? null))
      .catch(() => undefined);
  }, [environment]);

  useEffect(() => {
    refreshRunning();
    const interval = window.setInterval(refreshRunning, FIVE_SECONDS);
    return () => window.clearInterval(interval);
  }, [refreshRunning]);

  // The import of another administrator: a banner, and Apply waits for it; the own import is shown by the progress screen
  const otherImport = running?.running && !running.running.is_mine ? running.running : null;
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
    setStartedBy(null);
    setIsApplying(true);
    commitApply({
      variables: { file_id: fileId, selections, dry_run: false },
      onCompleted: () => {
        setIsApplying(false);
        refresh();
      },
      onError: (error) => {
        setIsApplying(false);
        if (getConfigPresetErrorReason(error) === 'file_missing') {
          setIsFileMissing(true);
        }
        // The toast shows the refusal; the step only adds who started the running import
        setStartedBy(getConfigPresetErrorReason(error) === 'import_running' ? getConfigPresetStartedBy(error) ?? null : null);
        refresh();
      },
    });
  };

  // The expected result of each item, nothing is written: the wizard stays on the preview
  const handleSimulate: ConfigPresetImportPreviewProps['onSimulate'] = (fileId, selections, { onCompleted, onError }) => {
    commitApply({
      variables: { file_id: fileId, selections, dry_run: true },
      onCompleted: (response) => onCompleted(response.configPresetImport.results),
      onError,
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

  const handleBackToSelection = () => {
    commitBack({
      variables: {},
      onCompleted: () => {
        refresh();
      },
    });
  };

  const handleClose = () => {
    commitClear({ variables: { delete_file: false }, onCompleted: onFinish });
  };

  const renderStep = () => {
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
    if (step === 'interrupted' && session) {
      return <ConfigPresetImportInterrupted session={session} onBackToSelection={handleBackToSelection} onStartOver={handleStartOver} />;
    }
    if (step === 'result' && session) {
      return <ConfigPresetImportResult session={session} onClose={handleClose} />;
    }
    return (
      <ConfigPresetImportPreview
        key={session?.file_id}
        session={session!}
        isOtherImportRunning={otherImport !== null}
        lastFinishedAt={running?.last_finished_at}
        startedBy={startedBy}
        onApply={(selections) => handleApply(session!.file_id, selections)}
        onSimulate={handleSimulate}
        onStartOver={handleStartOver}
        onFileMissing={() => setIsFileMissing(true)}
      />
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      {otherImport && (
        <Alert
          severity="info"
          elevation={1}
          title={otherImport.name ? t_i18n('Import by {name} in progress', { values: { name: otherImport.name } }) : t_i18n('Import by another administrator in progress')}
          description={t_i18n('{processed} of {total}', { values: { processed: otherImport.processed, total: otherImport.total } })}
        />
      )}
      <ConfigPresetWizardStepper activeStep={{ welcome: 0, upload: 0, preview: 1, progress: 1, interrupted: 1, result: 2 }[step]} />
      {renderStep()}
    </div>
  );
};

export default ConfigPresetImportWizard;
