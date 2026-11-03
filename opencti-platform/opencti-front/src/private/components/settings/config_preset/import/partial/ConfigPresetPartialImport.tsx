import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { DialogActions } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Checkbox, type FileRejection, FileSelect, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../../components/i18n';
import type { Theme } from '../../../../../../components/Theme';
import useApiMutation from '../../../../../../utils/hooks/useApiMutation';
import { type ConfigImportMode, isConfigImportMode } from '../../configImportMode';
import ConfigPresetImportModeSelect from '../ConfigPresetImportModeSelect';
import ConfigPresetResultLine from '../ConfigPresetResultLine';
import { partialImportItemModes, partialImportSelectedKeys, toggleSelectedKey } from './configPresetPartialImportSelection';
import { ConfigPresetPartialImportPreviewMutation, ConfigPresetPartialImportPreviewMutation$data } from './__generated__/ConfigPresetPartialImportPreviewMutation.graphql';
import { ConfigPresetPartialImportMutation, ConfigPresetPartialImportMutation$data } from './__generated__/ConfigPresetPartialImportMutation.graphql';

const configPresetPartialImportPreviewMutation = graphql`
  mutation ConfigPresetPartialImportPreviewMutation($file: Upload!, $type: ID!) {
    configPresetPartialImportPreview(file: $file, type: $type) {
      bundle_name
      default_mode
      type {
        key
        modes
        items {
          key
          label
          translatable
          exists
          conflict
        }
      }
    }
  }
`;

const configPresetPartialImportMutation = graphql`
  mutation ConfigPresetPartialImportMutation($file: Upload!, $type: ID!, $items: [ID!]!, $item_modes: [ConfigPresetItemModeInput!]) {
    configPresetPartialImport(file: $file, type: $type, items: $items, item_modes: $item_modes) {
      results {
        type
        key
        status
        reason
        label
        translatable
      }
      counts {
        created
        overwritten
        skipped
        failed
      }
    }
  }
`;

type Preview = ConfigPresetPartialImportPreviewMutation$data['configPresetPartialImportPreview'];
type Output = ConfigPresetPartialImportMutation$data['configPresetPartialImport'];

// The same limit as the backend, which refuses a larger zip
const MAX_ZIP_SIZE = 50 * 1024 * 1024;

interface ConfigPresetPartialImportProps {
  // The key of the configuration preset type to take from the bundle (branding for the themes...)
  type: string;
  // What the dialog calls the items of the type, already translated (the themes...)
  itemsLabel: string;
  // After a real import, so that the screen reads its items again
  onImported?: () => void;
  onClose: () => void;
}

// The partial import of one type from a full configuration bundle, to put in a dialog: the bundle is picked, the items of the type
// are listed (every one selected), then the selected ones are imported. An item that already exists is added as a copy by default.
// Generic: any screen can offer it for its own type, the backend imports any type that has an importer.
const ConfigPresetPartialImport: FunctionComponent<ConfigPresetPartialImportProps> = ({ type, itemsLabel, onImported, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [modes, setModes] = useState<Record<string, ConfigImportMode>>({});
  const [output, setOutput] = useState<Output | null>(null);
  const [commitPreview, previewing] = useApiMutation<ConfigPresetPartialImportPreviewMutation>(configPresetPartialImportPreviewMutation);
  const [commitImport, importing] = useApiMutation<ConfigPresetPartialImportMutation>(configPresetPartialImportMutation);

  const items = preview?.type?.items ?? [];
  const defaultMode = isConfigImportMode(preview?.default_mode ?? '') ? preview?.default_mode as ConfigImportMode : null;
  const itemLabel = (item: { label: string; translatable: boolean }) => (item.translatable ? t_i18n(item.label) : item.label);
  const rejectionMessage = (rejections: FileRejection[]) => (
    rejections[0].reason === 'accept' ? t_i18n('This file is not in the specified format') : t_i18n('This file is too large')
  );

  const handleFile = (value: File) => {
    setFile(value);
    setPreview(null);
    setModes({});
    commitPreview({
      variables: { file: value, type },
      onCompleted: (data) => {
        const result = data.configPresetPartialImportPreview;
        setPreview(result);
        setSelected(partialImportSelectedKeys(result.type?.items ?? []));
      },
      onError: () => setFile(null),
    });
  };

  const handleImport = () => {
    if (!file) return;
    const selectedItems = items.filter(({ key }) => selected.has(key));
    commitImport({
      variables: {
        file,
        type,
        items: selectedItems.map(({ key }) => key),
        item_modes: defaultMode ? partialImportItemModes(selectedItems, modes, defaultMode) : [],
      },
      onCompleted: (data) => {
        setOutput(data.configPresetPartialImport);
        onImported?.();
      },
    });
  };

  if (output) {
    return (
      <>
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }} data-testid="config-preset-partial-import-result">
          <Text variant="content-base">
            {t_i18n('{created} created, {overwritten} overwritten, {skipped} skipped, {failed} failed', { values: output.counts })}
          </Text>
          {output.results.map((result) => (
            <ConfigPresetResultLine key={`${result.type}/${result.key}`} label={itemLabel(result)} status={result.status} reason={result.reason} />
          ))}
        </div>
        <DialogActions>
          <Button onClick={onClose}>{t_i18n('Close')}</Button>
        </DialogActions>
      </>
    );
  }

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(2) }}>
        <Text variant="content-base">{t_i18n('Select the configuration bundle (zip) exported from another platform.')}</Text>
        <FileSelect
          value={file}
          triggerLabel={t_i18n('Upload a configuration bundle')}
          placeholder={t_i18n('No file selected.')}
          accept=".zip,application/zip"
          maxSize={MAX_ZIP_SIZE}
          rejectionMessage={rejectionMessage}
          loading={previewing}
          disabled={previewing || importing}
          data-testid="config-preset-partial-import-file"
          onValueChange={(value) => {
            if (value instanceof File) {
              handleFile(value);
            } else if (value === null) {
              setFile(null);
              setPreview(null);
            }
          }}
        />
        {preview && preview.bundle_name && (
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
            {t_i18n('Bundle: {name}', { values: { name: preview.bundle_name } })}
          </Text>
        )}
        {preview && items.length === 0 && (
          <Text variant="content-base">{t_i18n('This configuration bundle holds no {items}.', { values: { items: itemsLabel } })}</Text>
        )}
        {items.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), width: '100%' }}>
            <Text variant="content-base">{t_i18n('Select the {items} to import', { values: { items: itemsLabel } })}</Text>
            {items.map((item) => (
              <div key={item.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
                <Checkbox
                  label={itemLabel(item)}
                  description={item.conflict ? t_i18n('Already exists') : undefined}
                  checked={selected.has(item.key)}
                  disabled={importing}
                  onCheckedChange={() => setSelected(toggleSelectedKey(selected, item.key))}
                />
                {item.conflict && defaultMode && selected.has(item.key) && (
                  <ConfigPresetImportModeSelect
                    subject={itemLabel(item)}
                    modes={preview?.type?.modes ?? []}
                    value={modes[item.key] ?? defaultMode}
                    purpose="When it already exists"
                    disabled={importing}
                    onChange={(mode) => setModes({ ...modes, [item.key]: mode })}
                  />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      <DialogActions>
        <Button variant="secondary" onClick={onClose} disabled={importing}>{t_i18n('Cancel')}</Button>
        <Button
          onClick={handleImport}
          disabled={!file || selected.size === 0 || previewing || importing}
          data-testid="config-preset-partial-import-submit"
        >
          {t_i18n('Import')}
        </Button>
      </DialogActions>
    </>
  );
};

export default ConfigPresetPartialImport;
