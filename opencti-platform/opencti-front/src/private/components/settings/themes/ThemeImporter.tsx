import React, { FormEvent, FunctionComponent } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { IconButton } from '@mui/material';
import { FileUpload } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import { ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';
import { ThemeImporterImportMutation } from './__generated__/ThemeImporterImportMutation.graphql';

const importMutation = graphql`
  mutation ThemeImporterImportMutation($file: Upload!) {
    themeImport(file: $file) { id }
  }
`;

interface ThemeImporterProps {
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
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
      onCompleted: () => { handleRefetch(); },
    });
  };

  return (
    <IconButton
      color="primary"
      aria-label={t_i18n('Import')}
      size="large"
      component="label"
      onChange={handleImport}
    >
      <FileUpload fontSize="small" />
      <VisuallyHiddenInput type="file" accept={'application/json'} />
    </IconButton>
  );
};

export default ThemeImporter;
