import React, { FunctionComponent, useCallback, useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import { Alert, Spinner, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { ConfigPresetImportPreviewQuery, ConfigPresetImportPreviewQuery$data } from './__generated__/ConfigPresetImportPreviewQuery.graphql';
import { ConfigPresetImportPreviewSaveMutation } from './__generated__/ConfigPresetImportPreviewSaveMutation.graphql';
import { toConfigImportModes, toConfigPresetSelection } from './configPresetImportSelection';
import { ConfigImportMode, ConfigImportModes, DEFAULT_CONFIG_IMPORT_MODE, withConfigImportMode } from '../configImportMode';
import ConfigPresetImportModeSelect from './ConfigPresetImportModeSelect';
import { getConfigPresetErrorReason } from './configPresetImportStep';
import { buildConfigPresetSelections, ConfigPresetSelection, getConfigPresetForcedItems, selectAllConfigPresetItems } from '../configPresetSelection';
import { ConfigPresetItemRow } from '../ConfigPresetItemRow';
import ConfigPresetImportActions from './ConfigPresetImportActions';
import ConfigPresetImportMessages from './ConfigPresetImportMessages';
import ConfigPresetResultLine from './ConfigPresetResultLine';
import ConfigPresetSelectionAccordion from '../ConfigPresetSelectionAccordion';
import type { ConfigPresetImportSession } from './ConfigPresetImportWizard';

const SAVE_DELAY_MS = 500;

const configPresetImportPreviewQuery = graphql`
  query ConfigPresetImportPreviewQuery($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) {
      bundle_name
      openCTI_version
      generated_at
      ignored
      types {
        key
        label
        description
        modes
        group {
          key
          label
        }
        items {
          key
          label
          translatable
          isDefault
          exists
          dependsOn {
            type
            key
          }
        }
      }
    }
  }
`;

const configPresetImportPreviewSaveMutation = graphql`
  mutation ConfigPresetImportPreviewSaveMutation($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $revision: Int!) {
    configPresetImportSessionSave(file_id: $file_id, selections: $selections, revision: $revision) {
      revision
    }
  }
`;

type Preview = ConfigPresetImportPreviewQuery$data['configPresetImportPreview'];
type PreviewType = Preview['types'][number];

// The list takes its counts from the items it was given: a bundle is read at once, there is no next page
const toCountedTypes = (types: ReadonlyArray<PreviewType>) => types.map((type) => ({ ...type, itemsPageInfo: { globalCount: type.items.length } }));

type ImportSelections = ReturnType<typeof buildConfigPresetSelections>;

// The expected result of a processed item
interface SimulatedResult {
  readonly type: string;
  readonly key: string;
  readonly status: string;
  readonly reason?: string | null;
}

export interface ConfigPresetImportPreviewProps {
  session: ConfigPresetImportSession;
  // An import of another administrator runs: Apply waits for it, the preview and the simulation stay available
  isOtherImportRunning: boolean;
  // When the last import ended: a change after a simulation makes its results obsolete
  lastFinishedAt?: string | null;
  // The administrator whose import refused the last Apply
  startedBy?: string | null;
  // Sends the real import: the selection is saved first
  onApply: (selections: ImportSelections) => void;
  // Simulates the import of the selection: reads only, the results come back through onCompleted
  onSimulate: (
    fileId: string,
    selections: ImportSelections,
    callbacks: { onCompleted: (results: ReadonlyArray<SimulatedResult>) => void; onError: (error: Error) => void },
  ) => void;
  onStartOver: () => void;
  onFileMissing: () => void;
}

const ConfigPresetImportPreview: FunctionComponent<ConfigPresetImportPreviewProps> = ({
  session,
  isOtherImportRunning,
  lastFinishedAt,
  startedBy,
  onApply,
  onSimulate,
  onStartOver,
  onFileMissing,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const environment = useRelayEnvironment();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<ConfigPresetSelection>({});
  // What the import does with the items that exist, by type; saved with the selection
  const [importModes, setImportModes] = useState<ConfigImportModes>({});
  const [confirmStartOver, setConfirmStartOver] = useState(false);
  // The expected results, by `<type>/<key>`: held here only, never saved; cleared when the selection changes
  const [results, setResults] = useState<Record<string, SimulatedResult> | null>(null);
  const [isOutdated, setIsOutdated] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [hasPlatformChanged, setHasPlatformChanged] = useState(false);
  // last_finished_at as it was when the simulation was sent
  const simulatedAtRef = useRef<string | null | undefined>(undefined);
  const isMountedRef = useRef(true);
  const [commitSave] = useApiMutation<ConfigPresetImportPreviewSaveMutation>(configPresetImportPreviewSaveMutation);
  // The revision only goes up: the backend ignores a lower one
  const revisionRef = useRef(session.revision);
  const pendingRef = useRef<ReturnType<typeof buildConfigPresetSelections> | null>(null);
  const timerRef = useRef<number | null>(null);
  const commitSaveRef = useRef(commitSave);
  commitSaveRef.current = commitSave;

  useEffect(() => {
    let active = true;
    fetchQuery<ConfigPresetImportPreviewQuery>(environment, configPresetImportPreviewQuery, { file_id: session.file_id }, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => {
        if (active && data) {
          const loaded = data.configPresetImportPreview;
          setPreview(loaded);
          // A new upload has no saved selection yet: every item starts selected, as in the export
          const isNew = session.revision === 0 && session.selections.length === 0;
          setSelection(isNew ? selectAllConfigPresetItems(loaded.types) : toConfigPresetSelection(session.selections));
          setImportModes(toConfigImportModes(session.selections));
        }
      })
      .catch((err) => {
        if (active) {
          const reason = getConfigPresetErrorReason(err);
          if (reason === 'file_missing') {
            onFileMissing();
          } else {
            setError(reason ?? 'error');
          }
        }
      });
    return () => {
      active = false;
    };
  // The preview is read once for a file
  }, [environment, session.file_id]);

  const flushSave = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (pendingRef.current) {
      const selections = pendingRef.current;
      pendingRef.current = null;
      // Saved in the background: a failure is notified by the global error toast
      commitSaveRef.current({ variables: { file_id: session.file_id, selections, revision: revisionRef.current } });
    }
  }, [session.file_id]);

  // A pending save is sent on close
  useEffect(() => flushSave, [flushSave]);
  useEffect(() => () => {
    isMountedRef.current = false;
  }, []);

  // A change of the selection clears the expected results: they no longer describe what would be imported
  const clearResults = () => {
    setHasPlatformChanged(false);
    if (results !== null) {
      setResults(null);
      setIsOutdated(true);
    }
  };

  const types = preview ? toCountedTypes(preview.types) : [];
  const forced = getConfigPresetForcedItems(types, selection);
  const selections = buildConfigPresetSelections(types, selection, importModes);

  // The selection and the modes are saved together, after a short delay
  const scheduleSave = (nextSelection: ConfigPresetSelection, nextImportModes: ConfigImportModes) => {
    clearResults();
    revisionRef.current += 1;
    pendingRef.current = buildConfigPresetSelections(types, nextSelection, nextImportModes);
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
    }
    timerRef.current = window.setTimeout(flushSave, SAVE_DELAY_MS);
  };

  const handleSelectionChange = (next: ConfigPresetSelection) => {
    setSelection(next);
    scheduleSave(next, importModes);
  };

  const handleImportModeChange = (typeKey: string, mode: ConfigImportMode) => {
    const next = withConfigImportMode(importModes, typeKey, mode);
    setImportModes(next);
    scheduleSave(selection, next);
  };

  const handleApply = () => {
    flushSave();
    onApply(selections);
  };

  // Another import ended since the simulation was sent: its results no longer describe the platform
  useEffect(() => {
    if (results !== null && lastFinishedAt !== simulatedAtRef.current) {
      setResults(null);
      setHasPlatformChanged(true);
    }
  // Only a change of the end date of the last import clears the results
  }, [lastFinishedAt]);

  const handleSimulate = () => {
    simulatedAtRef.current = lastFinishedAt;
    setHasPlatformChanged(false);
    setIsSimulating(true);
    onSimulate(session.file_id, selections, {
      // A response that arrives after the wizard was closed is dropped
      onCompleted: (simulated) => {
        if (isMountedRef.current) {
          setIsSimulating(false);
          setIsOutdated(false);
          setResults(Object.fromEntries(simulated.map((result) => [`${result.type}/${result.key}`, result])));
        }
      },
      onError: (err) => {
        if (isMountedRef.current) {
          setIsSimulating(false);
          if (getConfigPresetErrorReason(err) === 'file_missing') {
            onFileMissing();
          }
        }
      },
    });
  };

  if (error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        <Alert severity="error" title={t_i18n('This configuration bundle cannot be imported')} description={t_i18n('The file is not a valid configuration bundle, or it comes from a more recent platform.')} />
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={onStartOver}>{t_i18n('Start over')}</Button>
        </div>
      </div>
    );
  }
  if (!preview) {
    return <Spinner label={t_i18n('Loading')} />;
  }
  const itemsCount = preview.types.reduce((count, type) => count + type.items.length, 0);
  return (
    // The dialog scrolls: a minimum height gives the list room, and the footer sticks to the bottom of the visible part
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2), minHeight: '60vh' }}>
      <Text variant="title-sm">{preview.bundle_name ?? t_i18n('Configuration bundle')}</Text>
      <Text variant="content-base">{t_i18n('Everything is selected by default. Uncheck anything you do not want to import; the elements you do not select are not touched. Existing items are overwritten unless a type offers another choice: use Simulate to see the outcome of each one before you apply.')}</Text>
      {preview.ignored.length > 0 && (
        <Alert severity="info" title={t_i18n('Some files of the bundle cannot be imported')} description={preview.ignored.join(', ')} />
      )}
      <ConfigPresetSelectionAccordion
        types={types}
        selection={selection}
        forced={forced}
        disabled={isSimulating}
        collapseSingletons={false}
        expandTypes
        onSelectionChange={handleSelectionChange}
        renderTypeActions={(type) => (
          <ConfigPresetImportModeSelect
            typeLabel={t_i18n(type.label)}
            modes={type.modes}
            value={importModes[type.key] ?? DEFAULT_CONFIG_IMPORT_MODE}
            disabled={isSimulating}
            onChange={(mode) => handleImportModeChange(type.key, mode)}
          />
        )}
        renderItem={(type, item) => (
          <div data-testid={`config-preset-import-item-${type.key}-${item.key}`}>
            <ConfigPresetItemRow
              typeKey={type.key}
              item={item}
              selection={selection}
              forced={forced}
              disabled={isSimulating}
              onSelectionChange={handleSelectionChange}
              statusSlot={results?.[`${type.key}/${item.key}`]
                ? <ConfigPresetResultLine status={results[`${type.key}/${item.key}`].status} reason={results[`${type.key}/${item.key}`].reason} />
                : undefined}
            />
          </div>
        )}
      />
      <div
        style={{
          position: 'sticky',
          bottom: 0,
          zIndex: 1,
          marginTop: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: theme.spacing(2),
          paddingTop: theme.spacing(2),
          // The surface of the dialog, so that the footer hides what scrolls under it without drawing a box of its own
          background: 'var(--bg-elevation-default)',
          // The scroll area of the Dialog has a 4px vertical padding below the sticky footer, where the list would show through
          boxShadow: `0 ${theme.spacing(0.5)} 0 0 var(--bg-elevation-default)`,
        }}
      >
        <ConfigPresetImportMessages
          itemsCount={itemsCount}
          isOutdated={isOutdated}
          hasPlatformChanged={hasPlatformChanged}
          isOtherImportRunning={isOtherImportRunning}
          startedBy={startedBy}
        />
        <ConfigPresetImportActions
          hasSelection={selections.length > 0}
          isSimulating={isSimulating}
          isOtherImportRunning={isOtherImportRunning}
          onStartOver={() => setConfirmStartOver(true)}
          onSimulate={handleSimulate}
          onApply={handleApply}
        />
      </div>
      <Dialog open={confirmStartOver} size="small" title={t_i18n('Start over')} onClose={() => setConfirmStartOver(false)}>
        <Text variant="content-base">{t_i18n('The uploaded bundle and your selection will be deleted.')}</Text>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1), marginTop: theme.spacing(3) }}>
          <Button variant="secondary" onClick={() => setConfirmStartOver(false)}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={onStartOver}>{t_i18n('Start over')}</Button>
        </div>
      </Dialog>
    </div>
  );
};

export default ConfigPresetImportPreview;
