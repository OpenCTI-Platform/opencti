import React, { FormEvent, FunctionComponent, useRef, useState } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { Tooltip } from '@mui/material';
import IconButton from '@common/button/IconButton';
import { FileUploadOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import ConfigPresetPartialImportDialog from '../config_preset/import/partial/ConfigPresetPartialImportDialog';
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
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [open, setOpen] = useState(false);
  // The file picker of the theme file import, opened from the dialog in the click on its card
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [commit] = useApiMutation<ThemeImporterImportMutation>(
    importMutation,
    undefined,
    {
      successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}`,
      errorMessage: t_i18n('Failed to import theme'),
    },
  );

  const importThemeFile = (file: File) => {
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
      {/* The same file import as without the dialog: a file picked closes the dialog, and the import tells its outcome as before */}
      <VisuallyHiddenInput
        ref={fileInputRef}
        type="file"
        accept="application/json"
        onClick={handleClick}
        onChange={(event) => {
          if (event.target.files?.[0]) {
            setOpen(false);
          }
          handleImport(event);
        }}
        data-testid="import-theme-file"
      />
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
        onChooseFile={() => fileInputRef.current?.click()}
      />
    </>
  );
};

export default ThemeImporter;
