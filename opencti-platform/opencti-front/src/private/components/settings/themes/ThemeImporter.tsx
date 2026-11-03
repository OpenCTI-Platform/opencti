import React, { FormEvent, FunctionComponent, useState } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { DialogActions, Tooltip } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { type FileRejection, FileSelect } from '@filigran/design-system';
import { FileUploadOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import ConfigPresetPartialImport from '../config_preset/import/partial/ConfigPresetPartialImport';
import ConfigPresetImportSourceChoice, { type ConfigPresetImportSource } from '../config_preset/import/partial/ConfigPresetImportSourceChoice';
import useConfigPresetPartialImportAccess from '../config_preset/import/partial/useConfigPresetPartialImportAccess';
import { ThemeImporterImportMutation } from './__generated__/ThemeImporterImportMutation.graphql';
import { ThemeManagerQuery$variables } from './__generated__/ThemeManagerQuery.graphql';

const importMutation = graphql`
  mutation ThemeImporterImportMutation($file: Upload!) {
    themeImport(file: $file) { id }
  }
`;

// The configuration preset type of the themes
const THEMES_CONFIG_PRESET_TYPE = 'branding';

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
  const theme = useTheme<Theme>();
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [open, setOpen] = useState(false);
  const [source, setSource] = useState<ConfigPresetImportSource>('file');
  const [themeFile, setThemeFile] = useState<File | null>(null);

  const [commit, importing] = useApiMutation<ThemeImporterImportMutation>(
    importMutation,
    undefined,
    {
      successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}`,
      errorMessage: t_i18n('Failed to import theme'),
    },
  );

  const importThemeFile = (file: File, onImported?: () => void) => {
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
      onCompleted: () => {
        handleRefetch();
        onImported?.();
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

  const handleClose = () => {
    setOpen(false);
    setSource('file');
    setThemeFile(null);
  };

  const rejectionMessage = (rejections: FileRejection[]) => (
    rejections[0].reason === 'accept' ? t_i18n('This file is not in the specified format') : t_i18n('This file is too large')
  );

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
      <Dialog
        open={open}
        onClose={handleClose}
        title={t_i18n('Import a theme')}
        showCloseButton
      >
        <div style={{ marginBottom: theme.spacing(3) }}>
          <ConfigPresetImportSourceChoice
            value={source}
            onChange={setSource}
            fileLabel={t_i18n('Import a theme file')}
            fileDescription={t_i18n('A theme exported as a JSON file')}
            bundleDescription={t_i18n('Select the themes to import from a full configuration bundle (zip)')}
            disabled={importing}
          />
        </div>
        {source === 'bundle' && (
          <ConfigPresetPartialImport
            type={THEMES_CONFIG_PRESET_TYPE}
            itemsLabel={t_i18n('themes')}
            onImported={onThemesImported}
            onClose={handleClose}
          />
        )}
        {source === 'file' && (
          <>
            <div>
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
            </div>
            <DialogActions>
              <Button variant="secondary" onClick={handleClose} disabled={importing}>{t_i18n('Cancel')}</Button>
              <Button
                onClick={() => themeFile && importThemeFile(themeFile, handleClose)}
                disabled={!themeFile || importing}
                data-testid="import-theme-submit"
              >
                {t_i18n('Import')}
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </>
  );
};

export default ThemeImporter;
