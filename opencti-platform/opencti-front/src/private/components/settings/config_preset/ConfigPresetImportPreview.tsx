import React, { FunctionComponent, useCallback, useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql, useRelayEnvironment } from 'react-relay';
import { Alert, Checkbox, Chip, Spinner, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ConfigPresetImportPreviewQuery, ConfigPresetImportPreviewQuery$data } from './__generated__/ConfigPresetImportPreviewQuery.graphql';
import { ConfigPresetImportPreviewSaveMutation } from './__generated__/ConfigPresetImportPreviewSaveMutation.graphql';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { toConfigPresetSelection } from './configPresetImportSelection';
import {
  addEnterpriseEditionExclusions,
  dropEnterpriseEditionItems,
  excludeEnterpriseEditionItems,
  getEnterpriseEditionKeys,
  withoutEnterpriseEditionItems,
} from './configPresetImportEnterpriseEdition';
import { getConfigPresetErrorReason } from './configPresetImportStep';
import {
  buildConfigPresetSelections,
  ConfigPresetSelection,
  countConfigPresetCheckedItems,
  getConfigPresetCheckboxState,
  getConfigPresetForcedItems,
  groupConfigPresetTypes,
  selectAllConfigPresetItems,
  toggleConfigPresetTypes,
} from './configPresetSelection';
import { ConfigPresetItemRow } from './ConfigPresetExportItems';
import ConfigPresetResultLine from './ConfigPresetResultLine';
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
          requiresEnterpriseEdition
          fields {
            key
            value
            external_host
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
  const isEnterpriseEdition = useEnterpriseEdition();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<ConfigPresetSelection>({});
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
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
          const restored = isNew ? selectAllConfigPresetItems(loaded.types) : toConfigPresetSelection(session.selections);
          // A license that expired since the selection was saved: the items that need it are dropped
          setSelection(isEnterpriseEdition ? restored : dropEnterpriseEditionItems(restored, getEnterpriseEditionKeys(loaded.types)));
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
      setSaveState('saving');
      commitSaveRef.current({
        variables: { file_id: session.file_id, selections, revision: revisionRef.current },
        onCompleted: () => setSaveState('saved'),
        onError: () => setSaveState('error'),
      });
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

  // What the selection helpers see: without the Enterprise Edition, the items that need it are left out
  const types = preview ? toCountedTypes(withoutEnterpriseEditionItems(preview.types, isEnterpriseEdition)) : [];
  const enterpriseEditionKeys = preview ? getEnterpriseEditionKeys(preview.types) : {};
  const forced = getConfigPresetForcedItems(types, selection);
  // The backend never receives the items that need the Enterprise Edition on a Community platform
  const selections = addEnterpriseEditionExclusions(buildConfigPresetSelections(types, selection), isEnterpriseEdition ? {} : enterpriseEditionKeys);

  const handleSelectionChange = (next: ConfigPresetSelection) => {
    setSelection(next);
    clearResults();
    revisionRef.current += 1;
    pendingRef.current = buildConfigPresetSelections(types, next);
    setSaveState('saving');
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
    }
    timerRef.current = window.setTimeout(flushSave, SAVE_DELAY_MS);
  };

  const handleApply = () => {
    flushSave();
    onApply(selections);
  };

  // A license entered in the wizard: the items it unlocks are not ticked, and the results computed without it are cleared
  const wasEnterpriseEditionRef = useRef(isEnterpriseEdition);
  useEffect(() => {
    if (isEnterpriseEdition && !wasEnterpriseEditionRef.current) {
      setSelection((current) => excludeEnterpriseEditionItems(current, enterpriseEditionKeys));
      clearResults();
    }
    wasEnterpriseEditionRef.current = isEnterpriseEdition;
  // Only a change of the license matters
  }, [isEnterpriseEdition]);

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
  // The counted type of a type: without the items that need the Enterprise Edition on a Community platform
  const countedOf = (type: PreviewType) => types.find(({ key }) => key === type.key)!;
  const typeLabel = (type: PreviewType) => {
    const counted = countedOf(type);
    return `${t_i18n(type.label)} (${countConfigPresetCheckedItems([counted], selection, forced)}/${counted.itemsPageInfo.globalCount})`;
  };
  const saveHint = { idle: '', saving: t_i18n('Saving'), saved: t_i18n('Saved'), error: t_i18n('The selection could not be saved') }[saveState];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the elements to import. The elements you do not select are not touched.')}</Text>
      {preview.ignored.length > 0 && (
        <Alert severity="info" title={t_i18n('Some files of the bundle cannot be imported')} description={preview.ignored.join(', ')} />
      )}
      {!isEnterpriseEdition && Object.values(enterpriseEditionKeys).some((keys) => keys.length > 0) && <EnterpriseEditionButton inLine />}
      {groupConfigPresetTypes(toCountedTypes(preview.types)).map((group) => (
        <div key={group.key} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
          <Text variant="title-sm">{t_i18n(group.label)}</Text>
          {group.types.map((type) => (
            <div key={type.key} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
              <Checkbox
                label={typeLabel(type)}
                description={t_i18n(type.description)}
                checked={getConfigPresetCheckboxState([type], selection, forced)}
                disabled={isSimulating || countedOf(type).itemsPageInfo.globalCount === 0}
                onCheckedChange={(checked) => handleSelectionChange(toggleConfigPresetTypes(selection, [type], checked === true))}
              />
              <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), paddingLeft: theme.spacing(3.5) }}>
                {type.items.map((item) => (
                  <div key={item.key} data-testid={`config-preset-import-item-${type.key}-${item.key}`}>
                    <ConfigPresetItemRow
                      typeKey={type.key}
                      item={item}
                      selection={selection}
                      forced={forced}
                      disabled={isSimulating}
                      requiresEnterpriseEdition={item.requiresEnterpriseEdition}
                      onSelectionChange={handleSelectionChange}
                      statusSlot={results?.[`${type.key}/${item.key}`]
                        ? <ConfigPresetResultLine status={results[`${type.key}/${item.key}`].status} reason={results[`${type.key}/${item.key}`].reason} />
                        : undefined}
                    />
                    <div style={{ paddingLeft: theme.spacing(3.5) }}>
                      <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
                        {item.exists ? t_i18n('Already exists, will be overwritten') : t_i18n('New')}
                      </Text>
                      {item.fields.map((field) => (
                        <div key={field.key} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                          <Text variant="content-compact">{`${field.key}: ${field.value ?? t_i18n('Untouched')}`}</Text>
                          {field.external_host && <Chip label={t_i18n('External host')} severity="medium" />}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ))}
      {isOtherImportRunning && <Text variant="content-compact">{t_i18n('Apply is available once the import in progress is over.')}</Text>}
      {startedBy && <Text variant="content-compact">{t_i18n('Started by {name}', { values: { name: startedBy } })}</Text>}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Text variant="content-compact">
          {hasPlatformChanged ? t_i18n('The platform changed since your simulation') : (isOutdated ? t_i18n('Simulate again to update') : saveHint)}
        </Text>
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
          <Button variant="secondary" onClick={() => setConfirmStartOver(true)} disabled={isSimulating}>{t_i18n('Start over')}</Button>
          <Button variant="secondary" onClick={handleSimulate} disabled={selections.length === 0 || isSimulating}>{t_i18n('Simulate')}</Button>
          <Button onClick={handleApply} disabled={selections.length === 0 || isSimulating || isOtherImportRunning}>{t_i18n('Apply')}</Button>
        </div>
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
