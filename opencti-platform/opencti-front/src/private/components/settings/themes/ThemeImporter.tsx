import React, { FormEvent, FunctionComponent } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { Tooltip } from '@mui/material';
import IconButton from '@common/button/IconButton';
import { FileUploadOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import { ThemeImporterImportMutation } from './__generated__/ThemeImporterImportMutation.graphql';
import { ThemeManagerQuery$variables } from './__generated__/ThemeManagerQuery.graphql';

const importMutation = graphql`
  mutation ThemeImporterImportMutation($file: Upload!) {
    themeImport(file: $file) { id }
  }
`;

interface ThemeImporterProps {
  handleRefetch: () => Disposable;
  paginationOptions: ThemeManagerQuery$variables;
}

const ThemeImporter: FunctionComponent<ThemeImporterProps> = ({
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation<ThemeImporterImportMutation>(
    importMutation,
    undefined,
    {
      successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}`,
      errorMessage: t_i18n('Failed to import theme'),
    },
  );

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

  return (
    <Tooltip title={t_i18n('Import a theme')}>
      <IconButton
        color="primary"
        aria-label={t_i18n('Import')}
        size="small"
        component="label"
        onChange={handleImport}
        data-testid="import-theme-btn"
      >
        <FileUploadOutlined fontSize="small" />
        <VisuallyHiddenInput type="file" accept="application/json" onClick={handleClick} />
      </IconButton>
    </Tooltip>
  );
};

export default ThemeImporter;
