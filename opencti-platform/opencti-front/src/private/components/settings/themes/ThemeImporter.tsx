import React, { FormEvent, FunctionComponent, useEffect, useState } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { DialogActions, Tooltip } from '@mui/material';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import { FileSelect } from '@filigran/design-system';
import { FileUploadOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import ConfigPresetPartialImportDialog, { type ConfigPresetFileImportStepProps } from '../config_preset/import/partial/ConfigPresetPartialImportDialog';
import useConfigPresetPartialImportAccess from '../config_preset/import/partial/useConfigPresetPartialImportAccess';
import { useFileRejectionMessage } from '../config_preset/import/ConfigPresetBundleFileSelect';
import { ThemeImporterImportMutation } from './__generated__/ThemeImporterImportMutation.graphql';
import { ThemeManagerQuery$variables } from './__generated__/ThemeManagerQuery.graphql';

const importMutation = graphql`
  mutation ThemeImporterImportMutation($file: Upload!) {
    themeImport(file: $file) { id name }
  }
`;

// The configuration preset type of the themes
const THEMES_CONFIG_PRESET_TYPE = 'branding';

interface ThemeFileImportStepProps extends ConfigPresetFileImportStepProps {
  importing: boolean;
  importThemeFile: (file: File, onImported: (name: string) => void) => void;
}

// The second step of the dialog for a theme file: the file, then the import
const ThemeFileImportStep: FunctionComponent<ThemeFileImportStepProps> = ({ importing, importThemeFile, onBack, onImported, onBusyChange }) => {
  const { t_i18n } = useFormatter();
  const [themeFile, setThemeFile] = useState<File | null>(null);
  useEffect(() => {
    onBusyChange(importing);
  }, [importing]);
  // Unmounted (back, or the dialog closed): no longer busy
  useEffect(() => () => onBusyChange(false), []);
  const rejectionMessage = useFileRejectionMessage();
  return (
    <>
      <FileSelect
        value={themeFile}
        triggerLabel={t_i18n('Select a theme file')}
        placeholder={t_i18n('No file selected.')}
        accept=".json,application/json"
        rejectionMessage={rejectionMessage}
        disabled={importing}
        data-testid="import-theme-file"
        onValueChange={(value) => setThemeFile(value instanceof File ? value : null)}
      />
      <DialogActions>
        <Button variant="secondary" onClick={onBack} disabled={importing}>{t_i18n('Back')}</Button>
        <Button
          onClick={() => themeFile && importThemeFile(themeFile, onImported)}
          disabled={!themeFile || importing}
          data-testid="import-theme-submit"
        >
          {t_i18n('Import')}
        </Button>
      </DialogActions>
    </>
  );
};

interface ThemeImporterProps {
  handleRefetch: () => Disposable;
  // After the import of themes from a configuration bundle: the list reads its themes again
  onThemesImported: () => void;
  paginationOptions: ThemeManagerQuery$variables;
}

const ThemeImporter: FunctionComponent<ThemeImporterProps> = ({
  handleRefetch,
  onThemesImported,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [open, setOpen] = useState(false);

  const [commit, importing] = useApiMutation<ThemeImporterImportMutation>(
    importMutation,
    undefined,
    {
      successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}`,
      errorMessage: t_i18n('Failed to import theme'),
    },
  );

  const importThemeFile = (file: File, onImported?: (name: string) => void) => {
    commit({
      variables: { file },
      updater: (store: RecordSourceSelectorProxy) => {
        return insertNode(
          store,
          'Pagination_themes',
          paginationOptions,
          'themeImport',
        );
      },
      onCompleted: (data) => {
        handleRefetch();
        onImported?.(data.themeImport?.name ?? file.name);
      },
    });
  };

  // empty the input when clicking on it because the browser
  // doesn't retrigger onclick if it is the same file
  const handleClick = (event: React.MouseEvent<HTMLInputElement>) => {
    const target = event.currentTarget;
    target.value = '';
  };

  const handleImport = (event: FormEvent) => {
    const inputElement = event.target as HTMLInputElement;
    const file = inputElement.files?.[0];

    if (!file) return;

    importThemeFile(file);
  };

  // Without the partial import (not a BYPASS user, or the CONFIG_PRESET flag off), the theme file import stays as it is
  if (!canImportFromBundle) {
    return (
      <Tooltip title={t_i18n('Import a theme')}>
        <IconButton
          color="primary"
          size="small"
          component="label"
          onChange={handleImport}
          data-testid="import-theme-btn"
          aria-label={t_i18n('Import a theme')}
        >
          <FileUploadOutlined fontSize="small" />
          <VisuallyHiddenInput type="file" accept="application/json" onClick={handleClick} />
        </IconButton>
      </Tooltip>
    );
  }

  return (
    <>
      <Tooltip title={t_i18n('Import a theme')}>
        <IconButton
          color="primary"
          size="small"
          onClick={() => setOpen(true)}
          data-testid="import-theme-btn"
          aria-label={t_i18n('Import a theme')}
        >
          <FileUploadOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <ConfigPresetPartialImportDialog
        open={open}
        onClose={() => setOpen(false)}
        title={t_i18n('Import a theme')}
        type={THEMES_CONFIG_PRESET_TYPE}
        itemsLabel={t_i18n('themes')}
        fileLabel={t_i18n('Import a theme file')}
        fileDescription={t_i18n('A theme exported as a JSON file')}
        bundleDescription={t_i18n('Select the themes to import from a full configuration bundle (zip)')}
        onBundleImported={onThemesImported}
        renderFileImport={(stepProps) => (
          <ThemeFileImportStep {...stepProps} importing={importing} importThemeFile={importThemeFile} />
        )}
      />
    </>
  );
};

export default ThemeImporter;
