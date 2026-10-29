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
import {
  ConfigImportMode,
  ConfigImportModes,
  configImportModeKey,
  DEFAULT_CONFIG_IMPORT_MODE,
  sharedConfigImportMode,
  withConfigImportMode,
  withConfigImportModeForItems,
} from '../configImportMode';
import ConfigPresetImportModeSelect from './ConfigPresetImportModeSelect';
import { getConfigPresetErrorReason } from './configPresetImportStep';
import {
  buildConfigPresetSelections,
  ConfigPresetSelection,
  getConfigPresetForcedItems,
  isConfigPresetItemSelected,
  isSingletonConfigPresetType,
  selectAllConfigPresetItems,
} from '../configPresetSelection';
import { ConfigPresetItemRow } from '../ConfigPresetItemRow';
import ConfigPresetImportActions from './ConfigPresetImportActions';
import ConfigPresetImportMessages from './ConfigPresetImportMessages';
import ConfigPresetResultLine from './ConfigPresetResultLine';
import { translateConfigPresetEntityTypes } from '../configPresetEntityTypes';
import ConfigPresetSelectionAccordion from '../ConfigPresetSelectionAccordion';
import type { ConfigPresetImportSession } from './ConfigPresetImportWizard';

const SAVE_DELAY_MS = 500;
// The expected results wait for the changes to stop, but the first ones are asked at once
const SIMULATE_DELAY_MS = 300;

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
          conflict
          fields {
            key
            value
          }
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
  mutation ConfigPresetImportPreviewSaveMutation($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $revision: Int!) {
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

// A row shows what the import would do unless there is nothing to say: an item that is created as it is, or one that is overwritten
// and has its choice (the choice says it)
const isResultShown = (result: SimulatedResult, hasChoice: boolean) => {
  if (result.status === 'CREATED' && !result.reason) {
    return false;
  }
  return !(result.status === 'OVERWRITTEN' && hasChoice);
};

export interface ConfigPresetImportPreviewProps {
  session: ConfigPresetImportSession;
  // An import of another administrator runs: Apply waits for it, the preview and the expected results stay available
  isOtherImportRunning: boolean;
  // When the last import ended: the expected results are computed again, the platform is no longer the one they were computed on
  lastFinishedAt?: string | null;
  // The administrator whose import refused the last Apply
  startedBy?: string | null;
  // Sends the real import: the selection is saved first
  onApply: (selections: ImportSelections) => void;
  // The expected result of each item of the selection: reads only, the results come back through onCompleted
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
  // What the import does with the items that exist, by item; saved with the selection
  const [importModes, setImportModes] = useState<ConfigImportModes>({});
  const [confirmStartOver, setConfirmStartOver] = useState(false);
  // The expected results, by `<type>/<key>`: held here only, never saved; computed again when the selection changes
  const [results, setResults] = useState<Record<string, SimulatedResult> | null>(null);
  // True from a change of the selection until the results of the latest request are in: Apply waits
  const [isSimulating, setIsSimulating] = useState(false);
  // Only the response of the latest request is kept
  const simulationRef = useRef(0);
  const hasSimulatedRef = useRef(false);
  const isMountedRef = useRef(true);
  const onSimulateRef = useRef(onSimulate);
  onSimulateRef.current = onSimulate;
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

  // Resolved once the save is answered, whatever the answer. A failure is notified by the global error toast; a file that is no longer
  // the one of the session (another tab uploaded a new one) sends the wizard back to the upload.
  const flushSave = useCallback((): Promise<void> => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (!pendingRef.current) {
      return Promise.resolve();
    }
    const selections = pendingRef.current;
    pendingRef.current = null;
    return new Promise((resolve) => {
      commitSaveRef.current({
        variables: { file_id: session.file_id, selections, revision: revisionRef.current },
        onCompleted: () => resolve(),
        onError: (err) => {
          if (getConfigPresetErrorReason(err) === 'file_missing') {
            onFileMissing();
          }
          resolve();
        },
      });
    });
  }, [session.file_id]);

  // A pending save is sent on close
  useEffect(() => () => {
    flushSave();
  }, [flushSave]);
  useEffect(() => () => {
    isMountedRef.current = false;
  }, []);

  const types = preview ? toCountedTypes(preview.types) : [];
  const forced = getConfigPresetForcedItems(types, selection);
  const selections = buildConfigPresetSelections(types, selection, importModes, forced);
  // Selected, or required by a selected item
  const isImportedItem = (typeKey: string, itemKey: string) => (forced[typeKey] ?? []).includes(itemKey) || isConfigPresetItemSelected(selection, typeKey, itemKey);

  // The selection and the modes are saved together, after a short delay
  const scheduleSave = (nextSelection: ConfigPresetSelection, nextImportModes: ConfigImportModes) => {
    revisionRef.current += 1;
    pendingRef.current = buildConfigPresetSelections(types, nextSelection, nextImportModes, getConfigPresetForcedItems(types, nextSelection));
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
    }
    timerRef.current = window.setTimeout(flushSave, SAVE_DELAY_MS);
  };

  const handleSelectionChange = (next: ConfigPresetSelection) => {
    setSelection(next);
    scheduleSave(next, importModes);
  };

  const handleImportModeChange = (typeKey: string, itemKey: string, mode: ConfigImportMode) => {
    const next = withConfigImportMode(importModes, typeKey, itemKey, mode);
    setImportModes(next);
    scheduleSave(selection, next);
  };

  // The same mode for all the items of a type that conflict
  const handleTypeImportModeChange = (typeKey: string, itemKeys: ReadonlyArray<string>, mode: ConfigImportMode) => {
    const next = withConfigImportModeForItems(importModes, typeKey, itemKeys, mode);
    setImportModes(next);
    scheduleSave(selection, next);
  };

  // The import starts once the save is answered: the session only accepts a save while it is a draft, and the two requests would race
  const handleApply = () => {
    flushSave().then(() => onApply(selections));
  };

  // Another import ended since the expected results were computed: the platform is no longer the one they describe. The first date
  // that is read is not a change (the polling has no answer yet when the preview opens).
  const [platformVersion, setPlatformVersion] = useState(0);
  const lastFinishedAtRef = useRef(lastFinishedAt);
  useEffect(() => {
    if (lastFinishedAtRef.current !== undefined && lastFinishedAt !== lastFinishedAtRef.current) {
      setPlatformVersion((version) => version + 1);
    }
    lastFinishedAtRef.current = lastFinishedAt;
  }, [lastFinishedAt]);

  // The expected results are computed as soon as the preview is shown, and again after each change of the selection or of a mode
  // (and when another import ended), once the changes have stopped. Nothing is selected: nothing to compute.
  const selectionsKey = JSON.stringify(selections);
  useEffect(() => {
    if (!preview) {
      return undefined;
    }
    if (selections.length === 0) {
      simulationRef.current += 1;
      setResults(null);
      setIsSimulating(false);
      return undefined;
    }
    simulationRef.current += 1;
    const request = simulationRef.current;
    setIsSimulating(true);
    const delay = hasSimulatedRef.current ? SIMULATE_DELAY_MS : 0;
    const timer = window.setTimeout(() => {
      hasSimulatedRef.current = true;
      onSimulateRef.current(session.file_id, selections, {
        // A response that arrives after a newer request, or after the wizard was closed, is dropped
        onCompleted: (simulated) => {
          if (isMountedRef.current && request === simulationRef.current) {
            setIsSimulating(false);
            setResults(Object.fromEntries(simulated.map((result) => [`${result.type}/${result.key}`, result])));
          }
        },
        onError: (err) => {
          if (isMountedRef.current && request === simulationRef.current) {
            setIsSimulating(false);
            // The results of the previous selection no longer describe this one
            setResults(null);
            if (getConfigPresetErrorReason(err) === 'file_missing') {
              onFileMissing();
            }
          }
        },
      });
    }, delay);
    return () => window.clearTimeout(timer);
  // The selection as sent: a new array with the same content does not compute again
  }, [preview, selectionsKey, platformVersion]);

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
      <Text variant="content-base">
        {t_i18n('Everything is selected by default. Uncheck anything you do not want to import; the elements you do not select are not touched. An item that already exists is overwritten unless you choose to add it as a copy.')}
        {' '}
        {t_i18n('A value that the bundle does not carry is left as it is.')}
      </Text>
      {preview.ignored.length > 0 && (
        <Alert severity="info" title={t_i18n('Some files of the bundle cannot be imported')} description={preview.ignored.join(', ')} />
      )}
      <ConfigPresetSelectionAccordion
        types={types}
        selection={selection}
        forced={forced}
        expandTypes
        onSelectionChange={handleSelectionChange}
        renderTypeActions={(type) => {
          // From two items in conflict that are imported: with one, its own choice is enough, and an item that is not imported has none
          const conflictKeys = type.items.filter((item) => item.conflict && isImportedItem(type.key, item.key)).map((item) => item.key);
          if (type.modes.length < 2 || conflictKeys.length < 2) {
            return null;
          }
          return (
            <ConfigPresetImportModeSelect
              subject={t_i18n(type.label)}
              purpose="Apply to all"
              modes={type.modes}
              value={sharedConfigImportMode(importModes, type.key, conflictKeys)}
              onChange={(mode) => handleTypeImportModeChange(type.key, conflictKeys, mode)}
            />
          );
        }}
        renderItem={(type, item) => {
          // The choice is for an item that conflicts with the platform and is imported; the items that do not show nothing
          const hasChoice = item.conflict && isImportedItem(type.key, item.key) && type.modes.length > 1;
          const result = results?.[`${type.key}/${item.key}`];
          // The types the import hides: the row alone only says that the item is there
          // The platform points to a theme by its standard id: a copy of the default theme is another theme, the default stays the one it is
          const keepsDefaultTheme = hasChoice && item.isDefault && importModes[configImportModeKey(type.key, item.key)] === 'COPY';
          const hiddenTypes = isImportedItem(type.key, item.key) && type.key === 'hiddenEntityTypes' ? item.fields.find(({ key }) => key === 'hidden_entity_types')?.value : null;
          return (
            <div data-testid={`config-preset-import-item-${type.key}-${item.key}`}>
              <ConfigPresetItemRow
                typeKey={type.key}
                item={item}
                description={isSingletonConfigPresetType(type) ? t_i18n(type.description) : undefined}
                selection={selection}
                forced={forced}
                onSelectionChange={handleSelectionChange}
                statusSlot={(hasChoice || (result && isResultShown(result, hasChoice))) ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                    {hasChoice && (
                      <ConfigPresetImportModeSelect
                        subject={item.translatable ? t_i18n(item.label) : item.label}
                        purpose="When it already exists"
                        modes={type.modes}
                        value={importModes[configImportModeKey(type.key, item.key)] ?? DEFAULT_CONFIG_IMPORT_MODE}
                        onChange={(mode) => handleImportModeChange(type.key, item.key, mode)}
                      />
                    )}
                    {result && isResultShown(result, hasChoice) && <ConfigPresetResultLine status={result.status} reason={result.reason} />}
                  </div>
                ) : undefined}
              />
              {keepsDefaultTheme && (
                <Text variant="content-compact" style={{ color: theme.palette.text.secondary, marginLeft: theme.spacing(3.5) }}>
                  {t_i18n('The platform keeps its current default theme.')}
                </Text>
              )}
              {hiddenTypes && (
                <Text variant="content-compact" style={{ color: theme.palette.text.secondary, marginLeft: theme.spacing(3.5) }}>
                  {translateConfigPresetEntityTypes(t_i18n, hiddenTypes)}
                </Text>
              )}
            </div>
          );
        }}
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
          isSimulating={isSimulating}
          isOtherImportRunning={isOtherImportRunning}
          startedBy={startedBy}
        />
        <ConfigPresetImportActions
          hasSelection={selections.length > 0}
          isSimulating={isSimulating}
          isOtherImportRunning={isOtherImportRunning}
          onStartOver={() => setConfirmStartOver(true)}
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
