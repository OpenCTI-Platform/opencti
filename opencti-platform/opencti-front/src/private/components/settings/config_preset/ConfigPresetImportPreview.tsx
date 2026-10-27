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
import { toConfigPresetSelection } from './configPresetImportSelection';
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
const toCountedTypes = (types: Preview['types']) => types.map((type) => ({ ...type, itemsPageInfo: { globalCount: type.items.length } }));

interface ConfigPresetImportPreviewProps {
  session: ConfigPresetImportSession;
  // Sends the real import: the selection is saved first
  onApply: (selections: ReturnType<typeof buildConfigPresetSelections>) => void;
  onStartOver: () => void;
  onFileMissing: () => void;
}

const ConfigPresetImportPreview: FunctionComponent<ConfigPresetImportPreviewProps> = ({ session, onApply, onStartOver, onFileMissing }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const environment = useRelayEnvironment();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<ConfigPresetSelection>({});
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [confirmStartOver, setConfirmStartOver] = useState(false);
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

  const types = preview ? toCountedTypes(preview.types) : [];
  const forced = getConfigPresetForcedItems(types, selection);
  const selections = buildConfigPresetSelections(types, selection);

  const handleSelectionChange = (next: ConfigPresetSelection) => {
    setSelection(next);
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
  const typeLabel = (type: PreviewType & { itemsPageInfo: { globalCount: number } }) => {
    return `${t_i18n(type.label)} (${countConfigPresetCheckedItems([type], selection, forced)}/${type.itemsPageInfo.globalCount})`;
  };
  const saveHint = { idle: '', saving: t_i18n('Saving'), saved: t_i18n('Saved'), error: t_i18n('The selection could not be saved') }[saveState];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the elements to import. The elements you do not select are not touched.')}</Text>
      {preview.ignored.length > 0 && (
        <Alert severity="info" title={t_i18n('Some files of the bundle cannot be imported')} description={preview.ignored.join(', ')} />
      )}
      {groupConfigPresetTypes(toCountedTypes(preview.types)).map((group) => (
        <div key={group.key} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
          <Text variant="title-sm">{t_i18n(group.label)}</Text>
          {group.types.map((type) => (
            <div key={type.key} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
              <Checkbox
                label={typeLabel(type)}
                description={t_i18n(type.description)}
                checked={getConfigPresetCheckboxState([type], selection, forced)}
                onCheckedChange={(checked) => handleSelectionChange(toggleConfigPresetTypes(selection, [type], checked === true))}
              />
              <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), paddingLeft: theme.spacing(3.5) }}>
                {type.items.map((item) => (
                  <div key={item.key} data-testid={`config-preset-import-item-${type.key}-${item.key}`}>
                    <ConfigPresetItemRow typeKey={type.key} item={item} selection={selection} forced={forced} onSelectionChange={handleSelectionChange} />
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Text variant="content-compact">{saveHint}</Text>
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
          <Button variant="secondary" onClick={() => setConfirmStartOver(true)}>{t_i18n('Start over')}</Button>
          <Button onClick={handleApply} disabled={selections.length === 0}>{t_i18n('Apply')}</Button>
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
